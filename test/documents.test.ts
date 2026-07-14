import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import type * as Dashcore from "@dashevo/dashcore-lib";
import { createRawKeySigner } from "../src/index.js";
import { ensureLoaded } from "../src/adapter/protocol.js";
import type { DocumentAction, IdentitySnapshot } from "../src/index.js";
import {
  InvalidIdentitySnapshotError,
  InvalidPrivateKeyError,
  InvalidTransitionError,
  KeyPurposeMismatchError,
  KeySecurityLevelMismatchError,
  MissingStateError,
  UnsupportedTransitionTypeError,
} from "../src/index.js";

const req = createRequire(import.meta.url);
const { PrivateKey } = req("@dashevo/dashcore-lib") as typeof Dashcore;
// The tooling is untyped here; the test builds a contract fixture directly through it.
const wasm = req("@dashevo/wasm-dpp") as {
  default: () => Promise<unknown>;
  DashPlatformProtocol: new (entropy: { generate(): Uint8Array }) => {
    dataContract: { create(owner: unknown, nonce: bigint, schema: unknown): { toBuffer(): Uint8Array } };
  };
  Identifier: { from(b: Uint8Array): unknown };
};

const rawOf = (p: InstanceType<typeof PrivateKey>) =>
  Uint8Array.from((p.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
const pubOf = (p: InstanceType<typeof PrivateKey>) => Uint8Array.from(p.toPublicKey().toBuffer() as Buffer);

const authKey = new PrivateKey(undefined, "testnet");
const transferKey = new PrivateKey(undefined, "testnet");
const masterKey = new PrivateKey(undefined, "testnet");
const mediumKey = new PrivateKey(undefined, "testnet");
const criticalKey = new PrivateKey(undefined, "testnet");

const IDENTITY_ID = new Uint8Array(32).fill(5);
const DOC_ID = new Uint8Array(32).fill(9);

// key id 1, AUTHENTICATION purpose (0), HIGH security (2)
function identity(): IdentitySnapshot {
  return {
    network: "testnet",
    protocolVersion: 1,
    id: IDENTITY_ID,
    publicKeys: [{ id: 1, purpose: 0, securityLevel: 2, keyType: 0, disabled: false, data: pubOf(authKey) }],
  };
}

// A "note" contract with one string property, serialized to the bytes a caller would supply.
let contractCache: Uint8Array | undefined;
async function noteContract(): Promise<Uint8Array> {
  if (contractCache === undefined) {
    await wasm.default();
    const dpp = new wasm.DashPlatformProtocol({ generate: () => randomBytes(32) });
    const owner = wasm.Identifier.from(Buffer.from(IDENTITY_ID));
    const schema = {
      note: {
        type: "object",
        properties: { message: { type: "string", position: 0, maxLength: 63 } },
        additionalProperties: false,
      },
    };
    contractCache = Uint8Array.from(dpp.dataContract.create(owner, 1n, schema).toBuffer());
  }
  return contractCache;
}

// The same "note" contract but with the document type tightened to require a CRITICAL key.
let criticalContractCache: Uint8Array | undefined;
async function criticalContract(): Promise<Uint8Array> {
  if (criticalContractCache === undefined) {
    await wasm.default();
    const dpp = new wasm.DashPlatformProtocol({ generate: () => randomBytes(32) });
    const owner = wasm.Identifier.from(Buffer.from(IDENTITY_ID));
    const schema = {
      note: {
        type: "object",
        properties: { message: { type: "string", position: 0, maxLength: 63 } },
        additionalProperties: false,
        signatureSecurityLevelRequirement: 1, // CRITICAL only
      },
    };
    criticalContractCache = Uint8Array.from(dpp.dataContract.create(owner, 1n, schema).toBuffer());
  }
  return criticalContractCache;
}

// Read the first document's data back out of a signed documents-batch transition, to check what was
// actually signed.
async function firstSignedDocumentData(bytes: Uint8Array): Promise<Record<string, unknown>> {
  await wasm.default();
  const dpp = new wasm.DashPlatformProtocol({ generate: () => randomBytes(32) }) as unknown as {
    stateTransition: {
      createFromBuffer(b: Uint8Array): Promise<{ getTransitions(): Array<{ getData(): Record<string, unknown> }> }>;
    };
  };
  const st = await dpp.stateTransition.createFromBuffer(bytes);
  const first = st.getTransitions()[0];
  if (first === undefined) throw new Error("no document transition");
  return first.getData();
}

const createAction: DocumentAction = { action: "create", documentType: "note", data: { message: "hi" } };

test("signDocumentBatch builds a create batch and signs it with the authentication key", async () => {
  await ensureLoaded();
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract: await noteContract(),
    actions: [createAction],
    nonceContext: { contractNonce: 1n },
  });
  assert.equal(signed.transitionType, 1, "DocumentsBatch");
  assert.equal(signed.signingKeyId, 1);
  assert.ok(signed.signature.length > 0);
});

test("a mixed create, replace, and delete batch builds and signs", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const actions: DocumentAction[] = [
    createAction,
    { action: "replace", documentType: "note", id: DOC_ID, revision: 1n, data: { message: "updated" } },
    { action: "delete", documentType: "note", id: new Uint8Array(32).fill(3) },
  ];
  const signed = await signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract: await noteContract(),
    actions,
    nonceContext: { contractNonce: 2n },
  });
  assert.equal(signed.transitionType, 1);
  assert.equal(signed.signingKeyId, 1);
});

test("a malformed identity snapshot is refused before the clone with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const malformed = { network: "testnet", protocolVersion: 1 } as unknown as IdentitySnapshot; // no id, no publicKeys
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: malformed,
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0),
        actions: [createAction],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
});

test("a non-array actions or non-Uint8Array contract is refused with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0),
        actions: "nope" as unknown as [],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: undefined as unknown as Uint8Array,
        actions: [createAction],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("an empty batch is rejected before the contract is parsed", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions: [],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a replace without a target document id is rejected before the tooling is touched", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const bad: DocumentAction = { action: "replace", documentType: "note", id: new Uint8Array(0), revision: 1n, data: {} };
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions: [bad],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("an unknown document type is refused by the tooling as an InvalidTransitionError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract,
        actions: [{ action: "create", documentType: "nope", data: { message: "x" } }],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a document batch signed by a non-authentication key is refused at the authorization step", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const withTransfer: IdentitySnapshot = {
    ...identity(),
    // key id 2, TRANSFER purpose (3), CRITICAL security (1), wrong purpose for a document write
    publicKeys: [{ id: 2, purpose: 3, securityLevel: 1, keyType: 0, disabled: false, data: pubOf(transferKey) }],
  };
  const contract = await noteContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: withTransfer,
        privateKey: { raw: rawOf(transferKey) },
        contract,
        actions: [createAction],
        nonceContext: { contractNonce: 1n },
      }),
    KeyPurposeMismatchError,
  );
});

test("no contract nonce and no transport is a MissingStateError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract,
        actions: [createAction],
      }),
    MissingStateError,
  );
});

test("the contract nonce is drawn from a configured transport, not the identity nonce", async () => {
  let askedContract = false;
  let askedIdentity = false;
  const signer = createRawKeySigner({
    network: "testnet",
    transport: {
      async broadcast() {
        return { transitionHash: new Uint8Array(0), accepted: true };
      },
      async getIdentityNonce() {
        askedIdentity = true;
        return 7n;
      },
      async getIdentityContractNonce() {
        askedContract = true;
        return 4n;
      },
    },
  });
  const signed = await signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract: await noteContract(),
    actions: [createAction],
  });
  assert.equal(askedContract, true, "the per-contract nonce should be read");
  assert.equal(askedIdentity, false, "the identity nonce should not be read for a document batch");
  assert.equal(signed.transitionType, 1);
});

test("the batch is snapshotted at call time, so mutating the caller's array during the await is ignored", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  const mutable: DocumentAction[] = [createAction];
  const promise = signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract,
    actions: mutable,
    nonceContext: { contractNonce: 1n },
  });
  // Append an invalid action after the synchronous validation/snapshot. If construction used the live
  // caller array, this unknown document type would make it throw; the snapshot must ignore it.
  mutable.push({ action: "create", documentType: "nonexistent", data: {} });
  const signed = await promise;
  assert.equal(signed.transitionType, 1);
});

test("the general path refuses a documents batch (it cannot read the contract's key requirement)", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  // Build a real signed documents batch, then feed its bytes back through the general path and authorize.
  const signed = await signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract: await noteContract(),
    actions: [createAction],
    nonceContext: { contractNonce: 1n },
  });
  await assert.rejects(
    () => signer.signTransition({ identity: identity(), privateKey: { raw: rawOf(authKey) }, transition: signed.bytes }),
    UnsupportedTransitionTypeError,
  );
  await assert.rejects(
    () => signer.authorize({ identity: identity(), privateKey: { raw: rawOf(authKey) }, transition: signed.bytes }),
    UnsupportedTransitionTypeError,
  );
});

test("a contract that requires CRITICAL refuses a HIGH key (contract-specific tightening)", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await criticalContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(), // key id 1 is HIGH (security 2), below the contract's CRITICAL requirement
        privateKey: { raw: rawOf(authKey) },
        contract,
        actions: [createAction],
        nonceContext: { contractNonce: 1n },
      }),
    KeySecurityLevelMismatchError,
  );
});

test("a contract that requires CRITICAL accepts a CRITICAL key", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const withCritical: IdentitySnapshot = {
    ...identity(),
    // key id 3, AUTHENTICATION (0), CRITICAL (1), meets the contract's tightened requirement
    publicKeys: [{ id: 3, purpose: 0, securityLevel: 1, keyType: 0, disabled: false, data: pubOf(criticalKey) }],
  };
  const signed = await signer.signDocumentBatch({
    identity: withCritical,
    privateKey: { raw: rawOf(criticalKey) },
    contract: await criticalContract(),
    actions: [createAction],
    nonceContext: { contractNonce: 1n },
  });
  assert.equal(signed.signingKeyId, 3);
  assert.equal(signed.transitionType, 1);
});

test("the document data is snapshotted, so mutating it during the await does not change the signed content", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  const data: { message: string } = { message: "original" };
  const promise = signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract,
    actions: [{ action: "create", documentType: "note", data }],
    nonceContext: { contractNonce: 1n },
  });
  // Mutate the caller's data object during the async gap; the signed content must be the call-time value.
  data.message = "mutated after the call begins";
  const signed = await promise;
  const readBack = await firstSignedDocumentData(signed.bytes);
  assert.equal(readBack["message"], "original", "the call-time data must be what was signed");
});

test("document data containing a function is refused with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  const data = { message: "x", oops: () => 1 } as unknown as Record<string, unknown>; // a function is not cloneable
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract,
        actions: [{ action: "create", documentType: "note", data }],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a MASTER key is refused for a document write, since the protocol excludes master (derived [1,2,3])", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const withMaster: IdentitySnapshot = {
    ...identity(),
    // key id 0, AUTHENTICATION (0), MASTER (0), master cannot sign a document write
    publicKeys: [{ id: 0, purpose: 0, securityLevel: 0, keyType: 0, disabled: false, data: pubOf(masterKey) }],
  };
  const contract = await noteContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: withMaster,
        privateKey: { raw: rawOf(masterKey) },
        contract,
        actions: [createAction],
        nonceContext: { contractNonce: 1n },
      }),
    KeySecurityLevelMismatchError,
  );
});

test("a MEDIUM key is accepted for a document write, since the derived requirement allows it", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const withMedium: IdentitySnapshot = {
    ...identity(),
    // key id 4, AUTHENTICATION (0), MEDIUM (3), allowed for documents, rejected by the old hardcoded set
    publicKeys: [{ id: 4, purpose: 0, securityLevel: 3, keyType: 0, disabled: false, data: pubOf(mediumKey) }],
  };
  const signed = await signer.signDocumentBatch({
    identity: withMedium,
    privateKey: { raw: rawOf(mediumKey) },
    contract: await noteContract(),
    actions: [createAction],
    nonceContext: { contractNonce: 1n },
  });
  assert.equal(signed.signingKeyId, 4);
  assert.equal(signed.transitionType, 1);
});

test("a replace with a wrong-length document id is rejected with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const bad: DocumentAction = { action: "replace", documentType: "note", id: new Uint8Array(31).fill(9), revision: 1n, data: {} };
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions: [bad],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a batch that targets the same document id more than once is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const actions: DocumentAction[] = [
    { action: "replace", documentType: "note", id: DOC_ID, revision: 1n, data: { message: "a" } },
    { action: "delete", documentType: "note", id: DOC_ID },
  ];
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions,
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a batch over the client-side action bound is rejected before the contract is parsed", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const actions: DocumentAction[] = Array.from({ length: 1001 }, () => createAction);
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions,
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a null action element or a bigint discriminant is refused with a typed error, not a native error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  for (const badActions of [[null] as unknown as DocumentAction[], [{ action: 5n } as unknown as DocumentAction]]) {
    await assert.rejects(
      () =>
        signer.signDocumentBatch({
          identity: identity(),
          privateKey: { raw: rawOf(authKey) },
          contract: new Uint8Array(0),
          actions: badActions,
          nonceContext: { contractNonce: 1n },
        }),
      InvalidTransitionError,
    );
  }
});

test("a malformed private key is refused with a typed error, not a native TypeError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: undefined } as unknown as { raw: Uint8Array },
        contract: new Uint8Array(0),
        actions: [createAction],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidPrivateKeyError,
  );
});

test("an unknown action kind is refused rather than signed as a replace", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const bad = { action: "typo", documentType: "note", id: DOC_ID, revision: 1n, data: {} } as unknown as DocumentAction;
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions: [bad],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("cyclic document data is refused with a typed error, not an untyped RangeError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const cyclic: Record<string, unknown> = { message: "x" };
  cyclic["self"] = cyclic;
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // the clone throws in the synchronous pass, before this is used
        actions: [{ action: "create", documentType: "note", data: cyclic }],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a non-bigint replace revision is refused with a typed error, not a raw TypeError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const bad = { action: "replace", documentType: "note", id: DOC_ID, revision: 5, data: {} } as unknown as DocumentAction;
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions: [bad],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a non-bigint contract nonce is refused with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract,
        actions: [createAction],
        nonceContext: { contractNonce: 5 as unknown as bigint },
      }),
    InvalidTransitionError,
  );
});

test("a replace revision at or above the unsigned 64-bit maximum is rejected, not wrapped", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  for (const badRevision of [2n ** 64n, 2n ** 64n - 1n]) {
    const bad: DocumentAction = { action: "replace", documentType: "note", id: DOC_ID, revision: badRevision, data: {} };
    await assert.rejects(
      () =>
        signer.signDocumentBatch({
          identity: identity(),
          privateKey: { raw: rawOf(authKey) },
          contract: new Uint8Array(0), // validation short-circuits before this is used
          actions: [bad],
          nonceContext: { contractNonce: 1n },
        }),
      InvalidTransitionError,
    );
  }
});

test("a replace whose current revision is below 1 is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const bad: DocumentAction = { action: "replace", documentType: "note", id: DOC_ID, revision: 0n, data: {} };
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract: new Uint8Array(0), // validation short-circuits before this is used
        actions: [bad],
        nonceContext: { contractNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a contract nonce below 1 is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const contract = await noteContract();
  await assert.rejects(
    () =>
      signer.signDocumentBatch({
        identity: identity(),
        privateKey: { raw: rawOf(authKey) },
        contract,
        actions: [createAction],
        nonceContext: { contractNonce: 0n },
      }),
    InvalidTransitionError,
  );
});

test("a delete builds and signs against a schema with required fields (pins the tooling's behavior)", async () => {
  // A release review claimed the delete path breaks on required-field schemas because the factory
  // validates the placeholder data. Probed against the pinned tooling, it does not; this test pins that,
  // so a tooling upgrade that starts validating at creation is caught here rather than in production.
  await wasm.default();
  const dpp = new wasm.DashPlatformProtocol({ generate: () => randomBytes(32) });
  const owner = wasm.Identifier.from(Buffer.from(IDENTITY_ID));
  const schema = {
    strictnote: {
      type: "object",
      properties: { message: { type: "string", position: 0, maxLength: 63 } },
      required: ["message"],
      additionalProperties: false,
    },
  };
  const strictContract = Uint8Array.from(dpp.dataContract.create(owner, 1n, schema).toBuffer());
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signDocumentBatch({
    identity: identity(),
    privateKey: { raw: rawOf(authKey) },
    contract: strictContract,
    actions: [{ action: "delete", documentType: "strictnote", id: DOC_ID }],
    nonceContext: { contractNonce: 1n },
  });
  assert.equal(signed.transitionType, 1);
});

test("byteArray document properties sign in every representation (a consumer-reported class)", async () => {
  // The first real consumer reported byteArray fields failing when passed as Buffer or Uint8Array in its
  // environment (a vendored copy resolving a different wasm-dpp build). On the pinned tooling all three
  // representations pass; this pins that, so a tooling upgrade that narrows the accepted shapes is caught.
  await wasm.default();
  const dpp = new wasm.DashPlatformProtocol({ generate: () => randomBytes(32) });
  const owner = wasm.Identifier.from(Buffer.from(IDENTITY_ID));
  const schema = {
    votePreference: {
      type: "object",
      properties: {
        poolId: { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 0 },
        proposalHash: { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 1 },
        choice: { type: "string", maxLength: 32, position: 2 },
      },
      required: ["poolId", "proposalHash", "choice"],
      additionalProperties: false,
    },
  };
  const contract = Uint8Array.from(dpp.dataContract.create(owner, 1n, schema).toBuffer());
  const signer = createRawKeySigner({ network: "testnet" });
  const bytes32 = new Uint8Array(32).fill(9);
  for (const value of [Buffer.from(bytes32), Uint8Array.from(bytes32), [...bytes32]]) {
    const signed = await signer.signDocumentBatch({
      identity: identity(),
      privateKey: { raw: rawOf(authKey) },
      contract,
      actions: [
        {
          action: "create",
          documentType: "votePreference",
          data: { poolId: value as never, proposalHash: value as never, choice: "yes" },
        },
      ],
      nonceContext: { contractNonce: 1n },
    });
    assert.equal(signed.transitionType, 1);
  }
});
