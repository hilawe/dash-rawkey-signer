/**
 * The optional integration layer (DESIGN section 3, decision D1). It converts a tooling identity object,
 * as fetched through the `dash` SDK, into the library-owned {@link IdentitySnapshot} the core accepts.
 * The identity is read through a structural type, so this module depends on the shape of the SDK's
 * identity, not on the SDK package, and a tooling version change is contained here and the adapter rather
 * than reaching the core contract or the caller's code.
 */
import type { IdentitySnapshot, Network, RegisteredKey } from "./types.js";
import { InvalidIdentitySnapshotError, isRawKeySignerError } from "./errors.js";
import { validateIdentitySnapshot } from "./authorize.js";

/**
 * Normalize a balance or revision to a bigint. The tooling's getters return bigint, so that passes
 * through. A number is accepted only when it is a safe non-negative integer, since a larger number has
 * already lost precision before it could be converted, and a fractional or non-finite number would throw
 * an untyped error.
 */
function toBigint(value: bigint | number, field: string): bigint {
  if (typeof value === "bigint") return value;
  if (Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  throw new InvalidIdentitySnapshotError(`identity ${field} is not a safe non-negative integer`);
}

/** A registered key on a tooling identity, as this converter reads it. */
export interface DashIdentityKeyLike {
  getId(): number;
  getPurpose(): number;
  getSecurityLevel(): number;
  getType(): number;
  getData(): Uint8Array;
  /** A timestamp when the key is disabled, absent (undefined or null) when it is enabled. */
  getDisabledAt(): unknown;
}

/** A tooling identity, as this converter reads it. */
export interface DashIdentityLike {
  getId(): { toBuffer(): Uint8Array };
  getPublicKeys(): readonly DashIdentityKeyLike[];
  getBalance(): bigint | number;
  getRevision(): bigint | number;
}

/**
 * What the identity object does not itself carry and the caller must supply: the network the identity
 * lives on (for key encoding) and the platform protocol version (for building tooling objects). Both are
 * known to a caller that fetched the identity through a configured SDK client.
 */
export interface SnapshotOptions {
  readonly network: Network;
  readonly protocolVersion: number;
}

/**
 * Convert a fetched tooling identity into a library {@link IdentitySnapshot}. The returned snapshot owns
 * its bytes (the id and each key's data are copied), so a later mutation of the identity object cannot
 * change it. Disabled keys are marked from `getDisabledAt`, and balance and revision are normalized to
 * bigints.
 */
export function snapshotFromDashIdentity(identity: DashIdentityLike, options: SnapshotOptions): IdentitySnapshot {
  if (!identity || typeof identity !== "object") {
    throw new InvalidIdentitySnapshotError("the identity to convert must be a tooling identity object");
  }
  if (!options || typeof options !== "object") {
    throw new InvalidIdentitySnapshotError("snapshot options must supply the network and protocol version");
  }
  // Read the tooling getters, and validate the result, inside one boundary that translates any native
  // throw into a typed error, since the input is an external object whose shape this converter cannot
  // assume. That covers a missing getter, a non-iterable getPublicKeys, a getter that itself throws, and a
  // hostile field value that throws while validateIdentitySnapshot coerces it (a throwing Symbol.toPrimitive).
  // A typed error raised inside (a non-array key list, an out-of-precision balance, a failed validation)
  // passes through unchanged.
  try {
    const keys = identity.getPublicKeys();
    if (!Array.isArray(keys)) {
      throw new InvalidIdentitySnapshotError("the identity's public keys must be an array");
    }
    const publicKeys: RegisteredKey[] = keys.map((key) => ({
      id: key.getId(),
      purpose: key.getPurpose(),
      securityLevel: key.getSecurityLevel(),
      keyType: key.getType(),
      disabled: key.getDisabledAt() != null,
      data: Uint8Array.from(key.getData()),
    }));
    const snapshot: IdentitySnapshot = {
      network: options.network,
      protocolVersion: options.protocolVersion,
      id: Uint8Array.from(identity.getId().toBuffer()),
      publicKeys,
      balance: toBigint(identity.getBalance(), "balance"),
      revision: toBigint(identity.getRevision(), "revision"),
    };
    // Validate with the same structural check the flows use, inside this boundary, so an out-of-range or
    // hostile field is a typed error here rather than a native throw or a failure deeper in a flow.
    validateIdentitySnapshot(snapshot);
    return snapshot;
  } catch (e) {
    if (isRawKeySignerError(e)) throw e;
    throw new InvalidIdentitySnapshotError("the identity object could not be read as a tooling identity");
  }
}
