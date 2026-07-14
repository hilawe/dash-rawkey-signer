/**
 * Library-owned public types (DESIGN section 3, decision D1). The public surface exposes these rather
 * than the tooling's own entity types, so a tooling version change is contained to the adapter and the
 * `snapshotFromDashIdentity` helper, not the caller's code.
 */

/** The networks the library supports. `local` covers a local devnet, which uses testnet key encoding. */
export const NETWORKS = ["mainnet", "testnet", "local"] as const;
export type Network = (typeof NETWORKS)[number];

/** Key purpose, mirroring the protocol's enumeration. */
export const KeyPurpose = {
  AUTHENTICATION: 0,
  ENCRYPTION: 1,
  DECRYPTION: 2,
  TRANSFER: 3,
} as const;
export type KeyPurpose = (typeof KeyPurpose)[keyof typeof KeyPurpose];

/** Key security level, mirroring the protocol's enumeration. */
export const KeySecurityLevel = {
  MASTER: 0,
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
} as const;
export type KeySecurityLevel = (typeof KeySecurityLevel)[keyof typeof KeySecurityLevel];

/** Key type, mirroring the protocol's enumeration. v1 signs with ECDSA secp256k1 keys. */
export const KeyType = {
  ECDSA_SECP256K1: 0,
  BLS12_381: 1,
  ECDSA_HASH160: 2,
  BIP13_SCRIPT_HASH: 3,
  EDDSA_25519_HASH160: 4,
} as const;
export type KeyType = (typeof KeyType)[keyof typeof KeyType];

/**
 * A raw private key supplied by the caller. Prefer `raw` bytes for backend custody, since a `wif`
 * string is immutable and cannot be erased from the caller's heap (DESIGN section 5).
 */
export type PrivateKeyInput = { readonly wif: string } | { readonly raw: Uint8Array };

/**
 * A new public key to add to an identity (the hand-held add-key flow). The library derives the public
 * bytes from `privateKey` and signs the key's ownership witness with it, so the caller supplies the new
 * key's own private key here, distinct from the master key that signs the transition.
 */
export interface NewKeyInput {
  /** The key id to assign. Must not collide with an existing key on the identity. */
  readonly id: number;
  readonly purpose: number;
  readonly securityLevel: number;
  readonly keyType: number;
  /** The new key's private key, used to derive its public bytes and sign its ownership witness. */
  readonly privateKey: PrivateKeyInput;
  readonly readOnly?: boolean;
}

/** One public key registered on an identity, as the library sees it. */
export interface RegisteredKey {
  readonly id: number;
  readonly purpose: number;
  readonly securityLevel: number;
  readonly keyType: number;
  readonly disabled: boolean;
  /** The public key bytes, matched against a supplied private key's derived public key. */
  readonly data: Uint8Array;
}

/**
 * A document's properties, as a plain object keyed by the contract's document-type schema. Construction
 * checks the document type against the contract, but not the property shape; the network validates the
 * data fully, so malformed data surfaces as a broadcast rejection, not a construction error.
 */
export type DocumentData = Readonly<Record<string, unknown>>;

/**
 * One action in a document batch (DESIGN decision D4, section 3). A discriminated union so a batch can
 * mix kinds and each kind carries only its own evidence. Create versus replace is explicit, chosen by
 * the caller, never inferred by a hidden index lookup. `id` is the 32-byte document id, and a replace's
 * `revision` is the document's current on-chain revision, which the protocol increments for the replace.
 * A delete carries only the id: the protocol's delete transition does not bind a revision, so requiring
 * one here would be a false guarantee (it diverges from DESIGN section 3, which predates that finding).
 */
export type DocumentAction =
  | { readonly action: "create"; readonly documentType: string; readonly data: DocumentData }
  | {
      readonly action: "replace";
      readonly documentType: string;
      readonly id: Uint8Array;
      readonly revision: bigint;
      readonly data: DocumentData;
    }
  | { readonly action: "delete"; readonly documentType: string; readonly id: Uint8Array };

/**
 * A library-owned snapshot of an identity, the only identity representation the core accepts. Build one
 * from the tooling's identity object with `snapshotFromDashIdentity`, or assemble it directly for
 * offline use.
 */
export interface IdentitySnapshot {
  readonly network: Network;
  readonly protocolVersion: number;
  /** The 32-byte identity id. */
  readonly id: Uint8Array;
  readonly publicKeys: readonly RegisteredKey[];
  /** The credit balance, when known, used for the withdrawal preflight (DESIGN F9). */
  readonly balance?: bigint;
  /**
   * The identity's current revision, required by identity-update flows (add-key). The protocol sets the
   * transition's revision to this plus one, so a stale value is rejected by the network like a bad nonce.
   */
  readonly revision?: bigint;
}

/** A signed transition, library-owned. Carries the serialized bytes so a caller may broadcast it elsewhere. */
export interface SignedTransition {
  readonly bytes: Uint8Array;
  readonly transitionType: number;
  readonly authorId: Uint8Array;
  readonly signingKeyId: number;
  readonly signature: Uint8Array;
}

/** The outcome of a broadcast. */
export interface SubmissionResult {
  readonly transitionHash: Uint8Array;
  readonly accepted: boolean;
}

/** Explicit nonce state for offline construction, when no transport is available (DESIGN section 10). */
export interface NonceContext {
  readonly identityNonce?: bigint;
  readonly contractNonce?: bigint;
}

/** The result of a read-only possession and authorization check (`signer.authorize`). Unlocks nothing. */
export interface AuthorizedKeyInfo {
  readonly keyId: number;
  readonly purpose: number;
  readonly securityLevel: number;
}
