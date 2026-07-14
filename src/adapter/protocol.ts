/**
 * The protocol side of the tooling adapter (DESIGN section 7). This is the one module that touches
 * `@dashevo/wasm-dpp`: it parses a transition into a descriptor, derives the key requirement from the
 * protocol (never the caller, DESIGN F2/D6), builds the tooling's signing-key object, and signs. The
 * tooling's loose `any`-typed surface is confined here so the rest of the library stays strongly typed.
 */
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import type * as WasmDpp from "@dashevo/wasm-dpp";
import type { DocumentAction, IdentitySnapshot, RegisteredKey } from "../types.js";
import { InvalidTransitionError, UnsupportedTransitionTypeError } from "../errors.js";

const nodeRequire = createRequire(import.meta.url);
// wasm-dpp is CommonJS: loadDpp is its default export, the classes are named exports.
const wasm = nodeRequire("@dashevo/wasm-dpp") as typeof WasmDpp;

/** The v1 transition types, read from the tooling's own enumeration and validated at load. */
const stTypes = wasm.StateTransitionTypes as unknown as Record<string, number | undefined>;
function transitionTypeValue(name: string): number {
  const value = stTypes[name];
  if (typeof value !== "number") {
    throw new Error(`the tooling's StateTransitionTypes is missing "${name}"`);
  }
  return value;
}
export const TransitionType = {
  DocumentsBatch: transitionTypeValue("DocumentsBatch"),
  IdentityUpdate: transitionTypeValue("IdentityUpdate"),
  IdentityCreditWithdrawal: transitionTypeValue("IdentityCreditWithdrawal"),
} as const;

// One lazily-initialized DPP instance. loadDpp loads the WebAssembly, then the instance carries the
// factories used for parsing, construction, and signing.
let dppPromise: Promise<DppInstance> | null = null;
type DppInstance = {
  stateTransition: { createFromBuffer(bytes: Uint8Array): Promise<WasmTransition> };
  document: {
    create(contract: unknown, ownerId: unknown, documentType: string, data: unknown): WasmDocument;
    createStateTransition(batch: unknown, nonces: unknown): WasmTransition;
  };
  identity: {
    createIdentityCreditWithdrawalTransition(
      identityId: unknown,
      amount: bigint,
      coreFeePerByte: number,
      pooling: number,
      outputScript: Uint8Array,
      nonce: bigint,
    ): WasmTransition;
    createIdentityUpdateTransition(identity: unknown, nonce: bigint, publicKeys: unknown): WasmTransition;
  };
  dataContract: { createFromBuffer(bytes: Uint8Array): Promise<WasmContract> };
};
/** The tooling seeds document ids from this. The SDK passes the same shape (`crypto.randomBytes(32)`). */
interface EntropyGenerator {
  generate(): Uint8Array;
}
async function getDpp(): Promise<DppInstance> {
  if (dppPromise === null) {
    const loadDpp = (wasm as unknown as { default: () => Promise<unknown> }).default;
    dppPromise = loadDpp().then(() => {
      const Ctor = (wasm as unknown as { DashPlatformProtocol: new (entropy: EntropyGenerator) => DppInstance })
        .DashPlatformProtocol;
      // Construct with an entropy generator. The withdrawal and identity factories need none, but
      // document.create derives a new document's id from entropy and a bare instance panics inside the
      // wasm without a generator (spike finding, DESIGN section 7). One instance with a generator serves
      // every path. No protocol-version argument, so contract deserialization is not pinned to one version.
      return new Ctor({ generate: () => randomBytes(32) });
    });
  }
  return dppPromise;
}

/** Ensure the WebAssembly is loaded before constructing tooling objects directly. */
export async function ensureLoaded(): Promise<void> {
  await getDpp();
}

/** The tooling's transition object. Its surface is loose, so it is narrowed to what the adapter uses. */
export interface WasmTransition {
  getType(): number;
  getOwnerId?(): { toBuffer(): Uint8Array } | undefined;
  getIdentityId?(): { toBuffer(): Uint8Array } | undefined;
  getSignaturePublicKeyId(): number;
  getSignature(): Uint8Array;
  /**
   * The security levels this transition's signing key may hold, as the protocol computes them for this
   * transition (for a documents batch, tightened by the contract's document-type requirement). Absent on
   * transitions whose requirement is fixed by type (withdrawal, identity update), where the table stands.
   */
  getKeySecurityLevelRequirement?(): number[] | undefined;
  sign(identityPublicKey: unknown, privateKey: Uint8Array, bls: unknown): void;
  verifySignature?(identityPublicKey: unknown, bls: unknown): boolean;
  toBuffer(): Uint8Array;
}

/** A parsed data contract. Narrowed to the id and the per-type schema the flow reads. */
export interface WasmContract {
  getId(): { toBuffer(): Uint8Array; toString(): string };
  getDocumentSchema(documentType: string): { signatureSecurityLevelRequirement?: number } | undefined;
}

/** A tooling document, narrowed to the setters the replace and delete actions use. */
interface WasmDocument {
  setId(id: unknown): void;
  setRevision(revision: bigint): void;
}

/** What the transition requires of its signing key. Purposes and levels are sets the protocol allows. */
export interface KeyRequirement {
  readonly requiredPurposes: readonly number[];
  readonly allowedSecurityLevels: readonly number[];
}

/**
 * The key requirement for a transition type (DESIGN D6). The purpose is fixed by the type and the
 * protocol exposes no per-transition purpose, so it stands as written. The security levels here are the
 * protocol's defaults, used as a fallback; for a documents batch the authoritative set is read from the
 * transition itself by {@link deriveKeyRequirement}, which also picks up any contract-specific
 * tightening. Fails closed for any type without a known requirement (F2, F3).
 *
 * Documents: authentication purpose, security CRITICAL/HIGH/MEDIUM ([1,2,3]); the protocol excludes
 * MASTER from document writes. Withdrawal: transfer purpose, CRITICAL only. Identity update: master key.
 */
export function requirementFor(transitionType: number): KeyRequirement {
  switch (transitionType) {
    case TransitionType.DocumentsBatch:
      return { requiredPurposes: [0], allowedSecurityLevels: [1, 2, 3] };
    case TransitionType.IdentityCreditWithdrawal:
      return { requiredPurposes: [3], allowedSecurityLevels: [1] };
    case TransitionType.IdentityUpdate:
      return { requiredPurposes: [0], allowedSecurityLevels: [0] };
    default:
      throw new UnsupportedTransitionTypeError(
        `no key requirement is known for transition type ${transitionType}`,
        transitionType,
      );
  }
}

/**
 * Refuse, on the general path, a transition whose authoritative key requirement cannot be derived from
 * the transition alone. A documents batch needs its data contract to know the required key security level
 * (this tooling build does not carry it on the transition), so the general `signTransition` and
 * `authorize` cannot authorize it correctly and must direct the caller to `signDocumentBatch`, which has
 * the contract. Signing on the transition's static default would authorize a key the contract may reject,
 * which the escape hatch must not do (adversarial review, general-path authorization gap).
 */
export function refuseUnauthorizableOnGeneralPath(transitionType: number): void {
  if (transitionType === TransitionType.DocumentsBatch) {
    throw new UnsupportedTransitionTypeError(
      "a documents batch cannot be authorized on the general path without its data contract; use signDocumentBatch",
      transitionType,
    );
  }
}

/**
 * Derive the authoritative key requirement for a parsed transition (DESIGN F2/D6). The purpose comes
 * from the type table. The allowed security levels come from the transition's own
 * `getKeySecurityLevelRequirement` when it exposes them, so a documents batch is checked against exactly
 * the levels the tooling will enforce at signing (including the contract's tightening), rather than a
 * hardcoded guess; otherwise the type table's defaults stand. Both the general path and `authorize` use
 * this so the one authorization chokepoint matches what the protocol enforces.
 */
export function deriveKeyRequirement(parsed: ParsedTransition): KeyRequirement {
  const base = requirementFor(parsed.transitionType);
  const fromTransition = parsed.raw.getKeySecurityLevelRequirement?.();
  const allowedSecurityLevels =
    Array.isArray(fromTransition) && fromTransition.length > 0 && fromTransition.every((n) => typeof n === "number")
      ? fromTransition
      : base.allowedSecurityLevels;
  return { requiredPurposes: base.requiredPurposes, allowedSecurityLevels };
}

/** A parsed transition plus the fields the authorization step binds against. */
export interface ParsedTransition {
  readonly raw: WasmTransition;
  readonly transitionType: number;
  readonly authorId: Uint8Array;
}

/** Parse serialized transition bytes. Fails closed on anything the tooling cannot describe. */
export async function parseTransition(bytes: Uint8Array): Promise<ParsedTransition> {
  const dpp = await getDpp();
  let raw: WasmTransition;
  try {
    raw = await dpp.stateTransition.createFromBuffer(bytes);
  } catch {
    throw new InvalidTransitionError("the supplied transition could not be parsed by the tooling");
  }
  const transitionType = raw.getType();
  const author = raw.getOwnerId?.() ?? raw.getIdentityId?.();
  if (author === undefined || author === null) {
    throw new InvalidTransitionError("the transition does not expose an author identity id");
  }
  return { raw, transitionType, authorId: Uint8Array.from(author.toBuffer()) };
}

interface IpkSetters {
  setId(id: number): void;
  setType(t: number): void;
  setPurpose(p: number): void;
  setSecurityLevel(s: number): void;
  setReadOnly(r: boolean): void;
  setData(d: Uint8Array): void;
}

/**
 * Build a tooling IdentityPublicKey from a key spec. Shared by the signing-key and the identity builders.
 * The fields are range-checked upstream, but an in-range yet unsupported value (an unknown protocol
 * version or key type) makes the tooling throw a raw string, so the construction is wrapped to keep the
 * typed-error boundary (DESIGN R11).
 */
function newIdentityPublicKey(
  protocolVersion: number,
  spec: { id: number; keyType: number; purpose: number; securityLevel: number; data: Uint8Array; readOnly: boolean },
): IpkSetters {
  const IdentityPublicKey = (wasm as unknown as { IdentityPublicKey: new (v: number) => IpkSetters })
    .IdentityPublicKey;
  try {
    const ipk = new IdentityPublicKey(protocolVersion);
    ipk.setId(spec.id);
    ipk.setType(spec.keyType);
    ipk.setPurpose(spec.purpose);
    ipk.setSecurityLevel(spec.securityLevel);
    ipk.setReadOnly(spec.readOnly);
    ipk.setData(Buffer.from(spec.data));
    return ipk;
  } catch {
    throw new InvalidTransitionError("the tooling rejected the key, protocol version, or key type");
  }
}

/** Build the tooling's signing-key object from a library-owned registered key. */
export async function buildSigningKey(key: RegisteredKey, protocolVersion: number): Promise<unknown> {
  await ensureLoaded();
  return newIdentityPublicKey(protocolVersion, {
    id: key.id,
    keyType: key.keyType,
    purpose: key.purpose,
    securityLevel: key.securityLevel,
    data: key.data,
    readOnly: false,
  });
}

/** The bytes and metadata of a signed transition. */
export interface SignedBytes {
  readonly bytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly signingKeyId: number;
}

/**
 * Sign a parsed transition with the raw scalar, using the tooling's own signing primitive. Signing sets
 * the transition's signing-key id from the provided key, which binds it to the resolved key.
 */
export function signParsed(parsed: ParsedTransition, signingKey: unknown, scalar: Buffer): SignedBytes {
  try {
    parsed.raw.sign(signingKey, scalar, null);
  } catch {
    // The tooling refused the key even though authorization passed. Fail closed with a typed,
    // secret-free error; the cause is dropped so the scalar cannot leak through it (DESIGN R5).
    throw new InvalidTransitionError("the tooling refused to sign the transition with the resolved key");
  }
  return {
    bytes: Uint8Array.from(parsed.raw.toBuffer()),
    signature: Uint8Array.from(parsed.raw.getSignature()),
    signingKeyId: parsed.raw.getSignaturePublicKeyId(),
  };
}

/** Construct an unsigned credit-withdrawal transition through the tooling's own factory. */
export async function constructWithdrawal(params: {
  identityId: Uint8Array;
  amount: bigint;
  coreFeePerByte: number;
  outputScript: Uint8Array;
  nonce: bigint;
}): Promise<ParsedTransition> {
  const dpp = await getDpp();
  const Identifier = (wasm as unknown as { Identifier: { from(b: Uint8Array): unknown } }).Identifier;
  let raw: WasmTransition;
  try {
    const identifier = Identifier.from(Buffer.from(params.identityId));
    raw = dpp.identity.createIdentityCreditWithdrawalTransition(
      identifier,
      params.amount,
      params.coreFeePerByte,
      0,
      Buffer.from(params.outputScript),
      params.nonce,
    );
  } catch {
    throw new InvalidTransitionError("the withdrawal transition could not be constructed by the tooling");
  }
  return { raw, transitionType: raw.getType(), authorId: params.identityId };
}

/**
 * Reconstruct a data contract from its serialized bytes and return it with its id. The document flow
 * needs the id to scope the per-contract nonce before it can build the batch, so parsing is split out
 * from construction. Fails closed on bytes the tooling cannot parse.
 */
export async function loadContract(contractBytes: Uint8Array): Promise<{ contract: WasmContract; contractId: Uint8Array }> {
  const dpp = await getDpp();
  let contract: WasmContract;
  try {
    contract = await dpp.dataContract.createFromBuffer(Buffer.from(contractBytes));
  } catch {
    throw new InvalidTransitionError("the supplied data contract could not be parsed by the tooling");
  }
  return { contract, contractId: Uint8Array.from(contract.getId().toBuffer()) };
}

/** The protocol default document security requirement (MEDIUM) when a document type sets none. */
const DEFAULT_DOCUMENT_SECURITY_REQUIREMENT = 3;

/**
 * The key security levels the protocol allows for a document type whose `signatureSecurityLevelRequirement`
 * is `requiredLevel` (0 MASTER through 3 MEDIUM). A MASTER requirement admits only a master key; every
 * other requirement admits CRITICAL down to the required level and excludes master, so a stricter (lower)
 * requirement admits fewer levels. Matches the protocol's own mapping (MEDIUM -> [1,2,3], MASTER -> [0]).
 */
function allowedLevelsForRequirement(requiredLevel: number): number[] {
  const capped = Math.min(Math.max(Math.trunc(requiredLevel), 0), 3);
  if (capped === 0) return [0];
  const levels: number[] = [];
  for (let level = 1; level <= capped; level += 1) levels.push(level);
  return levels;
}

/**
 * The security levels a single key must fall in to sign a batch touching `documentTypes`, read from the
 * contract's per-type `signatureSecurityLevelRequirement` (default MEDIUM). The key must satisfy every
 * type, so the sets are intersected and the strictest wins. A batch mixing a master-only type with any
 * other yields an empty set, which authorization then rejects as unsignable by one key.
 */
export function documentSecurityLevels(contract: WasmContract, documentTypes: readonly string[]): number[] {
  let allowed: number[] | null = null;
  for (const documentType of documentTypes) {
    const schema = contract.getDocumentSchema(documentType);
    const required =
      typeof schema?.signatureSecurityLevelRequirement === "number"
        ? schema.signatureSecurityLevelRequirement
        : DEFAULT_DOCUMENT_SECURITY_REQUIREMENT;
    const set = new Set<number>(allowedLevelsForRequirement(required));
    allowed = allowed === null ? [...set] : allowed.filter((level) => set.has(level));
  }
  const levels = allowed ?? allowedLevelsForRequirement(DEFAULT_DOCUMENT_SECURITY_REQUIREMENT);
  return [...levels].sort((a, b) => a - b);
}

/**
 * Construct an unsigned documents-batch transition through the tooling's own factories. Each action
 * builds a document against the contract (which validates the document type), and a replace or delete
 * overrides the generated id with the target document's id and sets its current revision, which the
 * protocol increments for a replace. The per-contract nonce scopes the batch. Returns the transition
 * together with the contract-derived key security levels, which the tooling does not itself enforce at
 * signing in this build, so authorization must (DESIGN F2/D6).
 */
export async function constructDocumentBatch(params: {
  contract: WasmContract;
  identityId: Uint8Array;
  actions: readonly DocumentAction[];
  contractNonce: bigint;
}): Promise<{ parsed: ParsedTransition; allowedSecurityLevels: number[] }> {
  const dpp = await getDpp();
  const Identifier = (wasm as unknown as { Identifier: { from(b: Uint8Array): unknown } }).Identifier;
  let ownerId: unknown;
  try {
    ownerId = Identifier.from(Buffer.from(params.identityId));
  } catch {
    throw new InvalidTransitionError("the identity id is not a valid identifier");
  }

  const buckets: { create: WasmDocument[]; replace: WasmDocument[]; delete: WasmDocument[] } = {
    create: [],
    replace: [],
    delete: [],
  };
  for (const action of params.actions) {
    // The whole per-action body is guarded so any tooling refusal (unknown type, malformed id, invalid
    // data) becomes a typed error rather than a raw IdentifierError or wasm panic (DESIGN R11).
    let doc: WasmDocument;
    try {
      const data = action.action === "delete" ? {} : action.data;
      doc = dpp.document.create(params.contract, ownerId, action.documentType, data);
      if (action.action !== "create") {
        doc.setId(Identifier.from(Buffer.from(action.id)));
      }
      // A replace carries the current revision, which the protocol increments; a delete binds none.
      if (action.action === "replace") {
        doc.setRevision(action.revision);
      }
    } catch (err) {
      if (err instanceof InvalidTransitionError) throw err;
      throw new InvalidTransitionError(
        `the "${action.action}" action for document type "${action.documentType}" could not be constructed (unknown type, invalid id, or invalid data)`,
      );
    }
    buckets[action.action].push(doc);
  }

  // Only include the non-empty action kinds; the tooling rejects an empty array for a kind.
  const batch: Record<string, WasmDocument[]> = {};
  if (buckets.create.length > 0) batch.create = buckets.create;
  if (buckets.replace.length > 0) batch.replace = buckets.replace;
  if (buckets.delete.length > 0) batch.delete = buckets.delete;

  const nonces = {
    [(ownerId as { toString(): string }).toString()]: {
      [params.contract.getId().toString()]: params.contractNonce.toString(),
    },
  };
  let raw: WasmTransition;
  try {
    raw = dpp.document.createStateTransition(batch, nonces);
  } catch {
    throw new InvalidTransitionError("the documents batch could not be constructed by the tooling");
  }

  // Every document type was validated by document.create above, so reading its schema is safe here.
  let allowedSecurityLevels: number[];
  try {
    allowedSecurityLevels = documentSecurityLevels(
      params.contract,
      params.actions.map((action) => action.documentType),
    );
  } catch {
    throw new InvalidTransitionError("the contract's document security requirement could not be read");
  }

  const parsed: ParsedTransition = { raw, transitionType: raw.getType(), authorId: params.identityId };
  return { parsed, allowedSecurityLevels };
}

/** A tooling Identity, narrowed to the setters the identity builder uses. */
interface IdentitySetters {
  setId(id: unknown): void;
  setBalance(balance: bigint): void;
  setRevision(revision: bigint): void;
  setPublicKeys(keys: unknown[]): void;
}

/**
 * Build a tooling Identity from a snapshot for the identity-update factory. Its enabled registered keys
 * are included (the factory rejects an empty key list and needs the signing key present); disabled keys
 * are omitted, since the flow validates the new key id against the full snapshot separately. The revision
 * is required by the caller, as the transition's revision is set to it plus one.
 */
function buildWasmIdentity(snapshot: IdentitySnapshot): unknown {
  const Identity = (wasm as unknown as { Identity: new (v: number) => IdentitySetters }).Identity;
  const Identifier = (wasm as unknown as { Identifier: { from(b: Uint8Array): unknown } }).Identifier;
  const identity = new Identity(snapshot.protocolVersion);
  identity.setId(Identifier.from(Buffer.from(snapshot.id)));
  identity.setBalance(snapshot.balance ?? 0n);
  identity.setRevision(snapshot.revision ?? 0n);
  const keys = snapshot.publicKeys
    .filter((key) => !key.disabled)
    .map((key) =>
      newIdentityPublicKey(snapshot.protocolVersion, {
        id: key.id,
        keyType: key.keyType,
        purpose: key.purpose,
        securityLevel: key.securityLevel,
        data: key.data,
        readOnly: false,
      }),
    );
  identity.setPublicKeys(keys);
  return identity;
}

/** A tooling identity-public-key with an ownership witness, narrowed to what the add-key flow sets. */
interface WasmWitnessKey extends IpkSetters {
  setSignature(signature: Uint8Array): void;
}

/** The witness-signing surface of an identity-update transition, narrowed to the add-key sequence. */
interface WitnessSigningTransition {
  setSignaturePublicKeyId(id: number | undefined): void;
  signByPrivateKey(scalar: Uint8Array, keyType: number): void;
  getSignature(): Uint8Array;
  setSignature(signature: Uint8Array | undefined): void;
  setPublicKeysToAdd(keys: unknown[]): void;
}

/** The public bytes and metadata of a new key to add. The flow derives the public bytes from the key. */
export interface AddKeyDescriptor {
  readonly id: number;
  readonly purpose: number;
  readonly securityLevel: number;
  readonly keyType: number;
  readonly readOnly: boolean;
  readonly publicData: Uint8Array;
}

/**
 * Construct an unsigned identity add-key transition, and return it with the tooling's witness-key object.
 * The witness is not yet signed: the flow signs it with the new key (`signAddKeyWitness`) once the master
 * signing-key id is resolved, then the master key signs the transition. Fails closed on tooling refusal.
 */
export async function constructAddKey(params: {
  snapshot: IdentitySnapshot;
  nonce: bigint;
  newKey: AddKeyDescriptor;
}): Promise<{ parsed: ParsedTransition; witnessKey: WasmWitnessKey }> {
  const dpp = await getDpp();
  const WithWitness = (wasm as unknown as { IdentityPublicKeyWithWitness: new (v: number) => WasmWitnessKey })
    .IdentityPublicKeyWithWitness;
  let raw: WasmTransition;
  let witnessKey: WasmWitnessKey;
  try {
    witnessKey = new WithWitness(params.snapshot.protocolVersion);
    witnessKey.setId(params.newKey.id);
    witnessKey.setType(params.newKey.keyType);
    witnessKey.setPurpose(params.newKey.purpose);
    witnessKey.setSecurityLevel(params.newKey.securityLevel);
    witnessKey.setReadOnly(params.newKey.readOnly);
    witnessKey.setData(Buffer.from(params.newKey.publicData));
    const identity = buildWasmIdentity(params.snapshot);
    raw = dpp.identity.createIdentityUpdateTransition(identity, params.nonce, { add: [witnessKey] });
  } catch {
    throw new InvalidTransitionError("the add-key transition could not be constructed by the tooling");
  }
  return { parsed: { raw, transitionType: raw.getType(), authorId: params.snapshot.id }, witnessKey };
}

/**
 * Sign the new key's ownership witness. The new key signs the transition with the master signing-key id
 * set (that id is part of the signable bytes), the signature is stored on the key as its witness, then
 * cleared from the transition so the master key can sign it cleanly. Synchronous: `signByPrivateKey` is.
 */
export function signAddKeyWitness(
  parsed: ParsedTransition,
  witnessKey: WasmWitnessKey,
  masterKeyId: number,
  newKeyType: number,
  newScalar: Buffer,
): void {
  const ust = parsed.raw as unknown as WitnessSigningTransition;
  ust.setSignaturePublicKeyId(masterKeyId);
  ust.signByPrivateKey(newScalar, newKeyType);
  witnessKey.setSignature(ust.getSignature());
  ust.setSignature(undefined);
  ust.setSignaturePublicKeyId(undefined);
  ust.setPublicKeysToAdd([witnessKey]);
}
