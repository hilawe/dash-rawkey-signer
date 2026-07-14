/**
 * The hand-held documents-batch flow (DESIGN R2, decision D4). It reconstructs the data contract from
 * bytes, resolves the per-contract nonce, builds the batch through the tooling from the discriminated
 * actions, and joins the one signing path so the authorization step covers it identically to the general
 * path. Set `nonceContext.contractNonce` for offline construction, or configure a transport for the
 * nonce to be read. Create versus replace is explicit in each action, never inferred by an index lookup.
 */
import type {
  DocumentAction,
  DocumentData,
  IdentitySnapshot,
  NonceContext,
  PrivateKeyInput,
  SignedTransition,
} from "../types.js";
import type { NonceSource } from "../nonce.js";
import { constructDocumentBatch, loadContract } from "../adapter/protocol.js";
import { signParsedTransition } from "../sign.js";
import { snapshotIdentity } from "../authorize.js";
import { snapshotPrivateKey } from "../secret.js";
import { describeType, isUint64, MAX_UINT64, toHex } from "../util.js";
import { InvalidTransitionError, MissingStateError } from "../errors.js";

/**
 * A client-side sanity bound on the number of actions in one batch, to fail fast on pathological input
 * rather than build an enormous transition. It is not the protocol's limit: the network enforces the
 * authoritative per-transition size, which depends on each document's serialized size, and rejects an
 * oversized batch at broadcast. This bound sits well above any realistic recovery batch.
 */
const MAX_BATCH_ACTIONS = 1000;

/**
 * Deep-copy a document's data value so the snapshot is complete and owns its memory. The data is read
 * during construction, after the awaits below, so a live caller reference could change the signed content
 * after the call begins. Every byte view is copied into a fresh Uint8Array this library owns, which
 * isolates even a view backed by shared memory (`structuredClone` keeps a `SharedArrayBuffer`-backed view
 * shared). Valid document data is JSON-like values and byte arrays; a function, a symbol, or a cyclic
 * reference is refused with a typed error rather than escaping as an untyped `RangeError`. `path` holds the
 * objects on the current branch so a true cycle is caught while a shared (acyclic) reference is copied.
 */
function deepCloneData(value: unknown, path: WeakSet<object>): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "function" || typeof value === "symbol") {
      throw new InvalidTransitionError("document data must be plain values and byte arrays, not functions or symbols");
    }
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    // A block copy through set(), which is a straight memcpy over internal slots: it cannot dispatch an
    // overridden iterator, and the copy always lands in a fresh plain ArrayBuffer, even when the source
    // view is backed by shared memory.
    const view = value as ArrayBufferView;
    const copy = new Uint8Array(view.byteLength);
    copy.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    return copy;
  }
  if (value instanceof ArrayBuffer || (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer)) {
    const source = new Uint8Array(value);
    const copy = new Uint8Array(source.byteLength);
    copy.set(source);
    return copy;
  }
  if (path.has(value)) {
    throw new InvalidTransitionError("document data must not contain a cycle");
  }
  path.add(value);
  const cloned = Array.isArray(value)
    ? value.map((element) => deepCloneData(element, path))
    : Object.fromEntries(Object.entries(value).map(([key, element]) => [key, deepCloneData(element, path)]));
  path.delete(value);
  return cloned;
}

function cloneData(data: DocumentData): DocumentData {
  return deepCloneData(data, new WeakSet<object>()) as DocumentData;
}

export interface SignDocumentBatchParams {
  readonly identity: IdentitySnapshot;
  readonly privateKey: PrivateKeyInput;
  /** The serialized data contract the documents belong to. All actions in a batch share one contract. */
  readonly contract: Uint8Array;
  /** One or more document actions, each carrying its own evidence (DESIGN section 3). */
  readonly actions: readonly DocumentAction[];
  readonly nonceContext?: NonceContext;
}

export async function signDocumentBatch(
  ctx: { readonly nonceSource: NonceSource | undefined },
  params: SignDocumentBatchParams,
): Promise<SignedTransition> {
  // Structural guards before any length read or clone, so an untyped caller gets a typed error, not a
  // native TypeError.
  if (!Array.isArray(params.actions)) {
    throw new InvalidTransitionError("the documents batch actions must be an array");
  }
  if (!(params.contract instanceof Uint8Array)) {
    throw new InvalidTransitionError("the contract must be a Uint8Array of serialized contract bytes");
  }
  if (params.actions.length === 0) {
    throw new InvalidTransitionError("a documents batch needs at least one action");
  }
  if (params.actions.length > MAX_BATCH_ACTIONS) {
    throw new InvalidTransitionError(
      `a documents batch cannot exceed ${MAX_BATCH_ACTIONS} actions (a client-side sanity bound)`,
    );
  }
  // Validate and snapshot every caller-owned input in one synchronous pass, before any await, so nothing
  // this operation reads after the awaits below (loadContract, the nonce read, construction, signing) is
  // a live caller reference. A caller that mutates the actions, ids, data, contract bytes, identity, or
  // key during those awaits cannot slip a duplicate, a wrong-length id, a revision under 1, a different
  // contract, or different signed content past the checks (a time-of-check/time-of-use guard). An obvious
  // mistake fails here with a clear typed error rather than a wasm refusal or a doomed broadcast.
  const targetIds = new Set<string>();
  const actions: DocumentAction[] = params.actions.map((action) => {
    if (!action || typeof action !== "object") {
      throw new InvalidTransitionError("each document action must be an object");
    }
    if (action.action === "create") {
      return { action: "create", documentType: action.documentType, data: cloneData(action.data) };
    }
    // Fail closed on an unknown discriminant. TypeScript proves the union is exhaustive, but a runtime
    // caller (untyped, or via a cast) could pass anything, and it must not be signed as a silent replace.
    // describeType, not JSON.stringify or a template, since the discriminant could be a bigint or a hostile
    // object whose coercion would itself throw a native error.
    if (action.action !== "replace" && action.action !== "delete") {
      throw new InvalidTransitionError(
        `unknown document action kind ${describeType((action as { action: unknown }).action)}`,
      );
    }
    if (!(action.id instanceof Uint8Array) || action.id.length !== 32) {
      throw new InvalidTransitionError(`a ${action.action} action needs a 32-byte target document id`);
    }
    const id = Uint8Array.from(action.id);
    const key = toHex(id);
    if (targetIds.has(key)) {
      throw new InvalidTransitionError("a documents batch cannot target the same document id more than once");
    }
    targetIds.add(key);
    if (action.action === "delete") {
      return { action: "delete", documentType: action.documentType, id };
    }
    if (!isUint64(action.revision, 1n) || action.revision >= MAX_UINT64) {
      throw new InvalidTransitionError(
        "a replace needs the document's current revision, an unsigned 64-bit integer at least 1 with room to increment",
      );
    }
    return {
      action: "replace",
      documentType: action.documentType,
      id,
      revision: action.revision,
      data: cloneData(action.data),
    };
  });

  // The rest of the caller-owned inputs, copied now so the awaits below read only owned state.
  // snapshotIdentity reads each identity field once, copies the bytes, and validates the copy, so a
  // malformed snapshot surfaces a typed error and a changing getter cannot slip a different value past
  // validation. The raw key bytes are copied below, and the supplied nonce is a bigint captured by value.
  const identity = snapshotIdentity(params.identity);
  let contractBytes: Uint8Array;
  try {
    contractBytes = Uint8Array.from(params.contract);
  } catch {
    throw new InvalidTransitionError("the contract bytes could not be read");
  }
  const suppliedNonce = params.nonceContext?.contractNonce;
  // snapshotPrivateKey validates the structure and returns an owned copy with a typed error on malformed
  // input. It is the last statement before the try, so nothing between it and the finally can throw and
  // leave the copy unzeroed. A finally zeroes it on every path; the signing scalar is zeroed by SecretKey.
  const privateKey = snapshotPrivateKey(params.privateKey);
  try {
    const { contract, contractId } = await loadContract(contractBytes);

    let nonce = suppliedNonce;
    if (nonce === undefined) {
      if (ctx.nonceSource === undefined) {
        throw new MissingStateError(
          "a documents batch needs an identity-contract nonce; supply nonceContext or configure a transport",
        );
      }
      nonce = await ctx.nonceSource.nextIdentityContractNonce(identity.id, contractId);
    }
    if (!isUint64(nonce, 1n)) {
      throw new InvalidTransitionError("the identity-contract nonce must be an unsigned 64-bit integer at least 1");
    }

    const { parsed, allowedSecurityLevels } = await constructDocumentBatch({
      contract,
      identityId: identity.id,
      actions,
      contractNonce: nonce,
    });
    // The contract can require a stronger signing key than the protocol default for a document type; the
    // tooling does not enforce that at signing in this build, so the authorization step does, here.
    return await signParsedTransition(identity, privateKey, parsed, { allowedSecurityLevels });
  } finally {
    if ("raw" in privateKey) privateKey.raw.fill(0);
  }
}
