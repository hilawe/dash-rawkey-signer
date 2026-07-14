/**
 * The authorization step (DESIGN section 4, requirements R4 and R6). This is the security core: given an
 * identity snapshot, the public key derived from the caller's raw private key, and a descriptor of the
 * transition (produced by the adapter from the parsed transition and the protocol, never from the
 * caller), it binds the key, the identity, and the transition together and resolves the single key that
 * will sign, or throws the narrowest typed error.
 *
 * This module is pure and tooling-independent. The requirement in the descriptor is derived upstream
 * from the protocol (DESIGN F2), so a caller can never weaken it here.
 */
import type { IdentitySnapshot, RegisteredKey } from "./types.js";
import { NETWORKS } from "./types.js";
import { bytesEqual, describeType, isUint32, isUint64, toHex } from "./util.js";
import {
  AuthorIdentityMismatchError,
  KeyNotOnIdentityError,
  KeyPurposeMismatchError,
  KeySecurityLevelMismatchError,
  KeyDisabledError,
  DeclaredSigningKeyMismatchError,
  InvalidIdentitySnapshotError,
  isRawKeySignerError,
} from "./errors.js";

/**
 * What the transition requires of its signing key, derived by the adapter from the parsed transition
 * and the protocol. Purposes and security levels are the exact sets the protocol allows for this
 * transition, so membership is checked rather than an assumed ordering.
 */
export interface TransitionDescriptor {
  readonly transitionType: number;
  /** The identity that authors the transition, from the transition itself. */
  readonly authorId: Uint8Array;
  /** The purposes the protocol allows for the signing key of this transition. */
  readonly requiredPurposes: readonly number[];
  /** The security levels the protocol allows for the signing key of this transition. */
  readonly allowedSecurityLevels: readonly number[];
  /**
   * The signing-key id already set on the transition, if any. When present, the resolved key must be
   * exactly that registration, so a caller-built transition cannot name one key while being signed by
   * another.
   */
  readonly declaredSigningKeyId?: number;
}

/**
 * Validate that a snapshot is well formed for deterministic authorization and for tooling construction:
 * the protocol version and every key's numeric field are unsigned 32-bit, the balance (when present) is
 * unsigned 64-bit, key ids are unique, and public-key data is present. Every numeric field here reaches a
 * tooling setter that silently wraps out-of-range input, so an unchecked value would sign something other
 * than what was supplied, or resolve a key whose id differs from the one written. Callers assembling a
 * snapshot directly should run this; `authorizeKey` runs it defensively. Throws
 * {@link InvalidIdentitySnapshotError} on any violation.
 *
 * It is exported and can run outside the signer's error boundary, so it carries its own: a native throw
 * from reading the caller's object (a hostile getter) surfaces as the same typed error. Note that
 * validation alone cannot pin down an object whose getters change between reads; a path that goes on to
 * use the snapshot should use {@link snapshotIdentity}, which builds a single-read copy and validates that.
 */
export function validateIdentitySnapshot(identity: IdentitySnapshot): void {
  try {
    validateIdentitySnapshotFields(identity);
  } catch (e) {
    if (isRawKeySignerError(e)) throw e;
    throw new InvalidIdentitySnapshotError("the identity snapshot could not be read");
  }
}

function validateIdentitySnapshotFields(identity: IdentitySnapshot): void {
  // Structural checks first, so a malformed snapshot from an untyped caller surfaces a typed error rather
  // than a native TypeError from a later clone or iteration (DESIGN R11).
  if (!identity || typeof identity !== "object") {
    throw new InvalidIdentitySnapshotError("the identity snapshot must be an object");
  }
  // Fail closed on an unknown network rather than let downstream key encoding fall back silently.
  // `coreNetwork` maps anything that is not mainnet to testnet encoding, so an untyped caller passing a
  // missing or misspelled network would otherwise get testnet-encoded keys with no error naming the cause.
  if (!NETWORKS.includes(identity.network)) {
    throw new InvalidIdentitySnapshotError(
      `the identity network must be one of ${NETWORKS.map((n) => `'${n}'`).join(", ")} (received ${describeType(identity.network)})`,
    );
  }
  if (!isUint32(identity.protocolVersion)) {
    throw new InvalidIdentitySnapshotError(
      `protocol version is not an unsigned 32-bit integer (received ${describeType(identity.protocolVersion)})`,
    );
  }
  if (!(identity.id instanceof Uint8Array) || identity.id.length !== 32) {
    throw new InvalidIdentitySnapshotError("the identity id must be a 32-byte Uint8Array");
  }
  if (identity.balance !== undefined && !isUint64(identity.balance)) {
    throw new InvalidIdentitySnapshotError("the identity balance is not an unsigned 64-bit integer");
  }
  // Defense in depth: the add-key flow re-checks the revision with its own increment headroom before the
  // one tooling call that reads it, but the shared validator sanitizes the whole snapshot so no future
  // flow can forget (the tooling setter would silently wrap an out-of-range value).
  if (identity.revision !== undefined && !isUint64(identity.revision)) {
    throw new InvalidIdentitySnapshotError("the identity revision is not an unsigned 64-bit integer");
  }
  if (!Array.isArray(identity.publicKeys)) {
    throw new InvalidIdentitySnapshotError("the identity public keys must be an array");
  }
  const seen = new Set<number>();
  for (const k of identity.publicKeys) {
    if (!k || typeof k !== "object") {
      throw new InvalidIdentitySnapshotError("a registered key must be an object");
    }
    if (!isUint32(k.id) || !isUint32(k.keyType) || !isUint32(k.purpose) || !isUint32(k.securityLevel)) {
      // These are unsigned 32-bit in the protocol; a larger value is silently truncated by the tooling,
      // so the resolved or constructed key would not match what was supplied.
      throw new InvalidIdentitySnapshotError(
        `a registered key (id ${describeType(k.id)}) has an id, type, purpose, or security level outside the unsigned 32-bit range`,
      );
    }
    if (seen.has(k.id)) {
      throw new InvalidIdentitySnapshotError(`registered key id ${k.id} is duplicated`);
    }
    seen.add(k.id);
    if (!(k.data instanceof Uint8Array) || k.data.length === 0) {
      throw new InvalidIdentitySnapshotError(`registered key ${k.id} has empty or invalid public-key data`);
    }
  }
}

/**
 * Read a snapshot's fields exactly once, build an owned copy, and validate the copy. Single-read
 * construction is what makes the validation meaningful on hostile input: a getter that returned one value
 * during validation could return another during a later copy, so the copy is built first, from one read per
 * field, and the stable copy is what gets validated. Inherited fields are picked up (explicit reads walk the
 * prototype chain, unlike a spread) and unknown extra properties are dropped. Any native throw from a getter
 * or a hostile byte iterator surfaces as a typed {@link InvalidIdentitySnapshotError}, so the helper is safe
 * to call directly, outside the signer's error boundary. Used by every path that must not read the caller's
 * object after an await (the time-of-check/time-of-use discipline).
 */
export function snapshotIdentity(identity: IdentitySnapshot): IdentitySnapshot {
  let copy: IdentitySnapshot;
  try {
    if (!identity || typeof identity !== "object") {
      throw new InvalidIdentitySnapshotError("the identity snapshot must be an object");
    }
    // One read per field. Destructuring invokes each getter exactly once.
    const { network, protocolVersion, id, publicKeys, balance, revision } = identity;
    if (!Array.isArray(publicKeys)) {
      throw new InvalidIdentitySnapshotError("the identity public keys must be an array");
    }
    // Copy the keys with indexed reads into a fresh library-owned array. A method dispatched through the
    // caller's array (map, slice) could be overridden to return the caller's own array, aliasing what the
    // snapshot promises to own. The length is read once.
    const keyCount = publicKeys.length;
    const copiedKeys: RegisteredKey[] = [];
    for (let i = 0; i < keyCount; i += 1) {
      const key = publicKeys[i];
      if (!key || typeof key !== "object") {
        throw new InvalidIdentitySnapshotError("a registered key must be an object");
      }
      const { id: keyId, purpose, securityLevel, keyType, disabled, data } = key;
      copiedKeys.push({
        id: keyId,
        purpose,
        securityLevel,
        keyType,
        disabled: Boolean(disabled),
        data: data instanceof Uint8Array ? Uint8Array.from(data) : data,
      });
    }
    copy = {
      network,
      protocolVersion,
      id: id instanceof Uint8Array ? Uint8Array.from(id) : id,
      publicKeys: copiedKeys,
      ...(balance !== undefined ? { balance } : {}),
      ...(revision !== undefined ? { revision } : {}),
    };
  } catch (e) {
    if (isRawKeySignerError(e)) throw e;
    throw new InvalidIdentitySnapshotError("the identity snapshot could not be read");
  }
  // The copy is stable (plain values and owned bytes), so this validation cannot be raced or re-read.
  validateIdentitySnapshot(copy);
  return copy;
}

/** Check one specific key against the requirement, in order, returning it or throwing its narrow failure. */
function checkKey(k: RegisteredKey, descriptor: TransitionDescriptor): RegisteredKey {
  if (!descriptor.requiredPurposes.includes(k.purpose)) {
    throw new KeyPurposeMismatchError(k.id, k.purpose, descriptor.requiredPurposes, descriptor.transitionType);
  }
  if (!descriptor.allowedSecurityLevels.includes(k.securityLevel)) {
    throw new KeySecurityLevelMismatchError(
      k.id,
      k.securityLevel,
      descriptor.allowedSecurityLevels,
      descriptor.transitionType,
    );
  }
  if (k.disabled) {
    throw new KeyDisabledError(k.id);
  }
  return k;
}

/** How far a key got toward eligibility, for choosing which match's failure to report. */
function progress(k: RegisteredKey, descriptor: TransitionDescriptor): number {
  const purposeOk = descriptor.requiredPurposes.includes(k.purpose) ? 4 : 0;
  const securityOk = descriptor.allowedSecurityLevels.includes(k.securityLevel) ? 2 : 0;
  const enabled = k.disabled ? 0 : 1;
  return purposeOk + securityOk + enabled;
}

/**
 * Resolve and authorize the single key that will sign `descriptor`'s transition for `identity`, using
 * the public key derived from the caller's raw key. Throws the narrowest typed error on any failure.
 */
export function authorizeKey(
  identity: IdentitySnapshot,
  derivedPublicKey: Uint8Array,
  descriptor: TransitionDescriptor,
): RegisteredKey {
  validateIdentitySnapshot(identity);

  // The transition must be authored by the supplied identity.
  if (!bytesEqual(descriptor.authorId, identity.id)) {
    throw new AuthorIdentityMismatchError(toHex(identity.id), toHex(descriptor.authorId));
  }

  // Every registered key whose bytes match the derived public key.
  const matches = identity.publicKeys.filter((k) => bytesEqual(k.data, derivedPublicKey));
  if (matches.length === 0) {
    throw new KeyNotOnIdentityError("the supplied key is not registered on the identity");
  }

  // When the transition already declares a signing-key id, that exact registration is the sole
  // candidate. Report its own eligibility failure, not another match's.
  if (descriptor.declaredSigningKeyId !== undefined) {
    const declared = matches.find((k) => k.id === descriptor.declaredSigningKeyId);
    if (declared === undefined) {
      throw new DeclaredSigningKeyMismatchError(descriptor.declaredSigningKeyId);
    }
    return checkKey(declared, descriptor);
  }

  // Otherwise resolve among fully eligible matches, deterministically by lowest key id. They are
  // interchangeable for authorization, and either produces a verifying signature (DESIGN section 4).
  const eligible = matches.filter((k) => progress(k, descriptor) === 7);
  if (eligible.length > 0) {
    return eligible.reduce((lowest, k) => (k.id < lowest.id ? k : lowest));
  }

  // No eligible match: report the narrowest failure, from the match that progressed furthest.
  const best = matches.reduce((a, b) => (progress(b, descriptor) > progress(a, descriptor) ? b : a));
  return checkKey(best, descriptor);
}
