/**
 * The optional integration layer (DESIGN section 3, decision D1). It converts a tooling identity object,
 * as fetched through the `dash` SDK, into the library-owned {@link IdentitySnapshot} the core accepts.
 * The identity is read through a structural type, so this module depends on the shape of the SDK's
 * identity, not on the SDK package, and a tooling version change is contained here and the adapter rather
 * than reaching the core contract or the caller's code.
 */
import type { IdentitySnapshot, Network, RegisteredKey } from "./types.js";
import { createHash } from "node:crypto";
import type { Transport } from "./adapter/transport.js";
import {
  BroadcastError,
  ClientRequiredError,
  InvalidIdentitySnapshotError,
  isRawKeySignerError,
  NetworkError,
} from "./errors.js";
import { toHex } from "./util.js";
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

// --- The SDK transport helper ---

/** The slice of the SDK's DAPI platform surface this helper forwards to, read structurally. */
export interface DashDapiPlatformLike {
  broadcastStateTransition(bytes: Uint8Array): Promise<unknown>;
  waitForStateTransitionResult(
    hash: Uint8Array,
    options: { prove: boolean },
  ): Promise<{ error?: { code?: number; message?: string } | null } | undefined>;
  getIdentityNonce(identityId: Uint8Array): Promise<{ identityNonce: bigint | number }>;
  getIdentityContractNonce(
    identityId: Uint8Array,
    contractId: Uint8Array,
  ): Promise<{ identityContractNonce: bigint | number }>;
}

/** A configured dash SDK client, as this helper reads it. Only getDAPIClient is touched. */
export interface DashSdkClientLike {
  getDAPIClient(): { platform: DashDapiPlatformLike };
}

/** Convert an SDK nonce value to bigint, failing with a typed transport error on a bad shape. */
function nonceToBigint(value: unknown, what: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  throw new NetworkError(`the SDK returned an invalid ${what}`);
}

/** An owned block copy of caller or SDK bytes; set() is a memcpy that dispatches no overridable iterator. */
function ownedCopy(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

/** Read a numeric code off a thrown SDK value without letting a hostile getter escape. */
function thrownCode(value: unknown): number | undefined {
  try {
    const code = (value as { code?: unknown } | null)?.code;
    return typeof code === "number" ? code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * gRPC status codes that mean the request never reached a verdict, so delivery is indeterminate: 4
 * DEADLINE_EXCEEDED and 14 UNAVAILABLE. The SDK stamps numeric codes on both platform rejections and
 * transport failures, so a numeric code alone does not prove a rejection; these are treated as transport.
 */
const TRANSPORT_CODES = new Set<number>([4, 14]);

/** Safely read a rejection {code, message} off an SDK result, translating a hostile shape to a typed error. */
function readRejection(result: unknown): { code?: number; message?: string } | null {
  if (result === undefined || result === null) return null;
  if (typeof result !== "object") {
    throw new NetworkError("the SDK returned an unrecognizable broadcast result");
  }
  const error = (result as { error?: unknown }).error;
  if (error === undefined || error === null) return null;
  if (typeof error !== "object") {
    throw new NetworkError("the SDK returned an unrecognizable broadcast error");
  }
  const code = (error as { code?: unknown }).code;
  const message = (error as { message?: unknown }).message;
  return {
    ...(typeof code === "number" ? { code } : {}),
    ...(message === undefined ? {} : { message: String(message) }),
  };
}

/**
 * Wrap a configured dash SDK client into the {@link Transport} this library expects, so the common
 * online pairing (the SDK fetches and broadcasts, this library signs) is a one-line setup:
 *
 *   const signer = createRawKeySigner({ network: "testnet", transport: createDashTransport(client) });
 *
 * Broadcast submits the signed bytes and waits for the platform's result with proof, matching the SDK's
 * own hash discipline (one sha256 over the signed bytes). The error model is phase-aware. A platform
 * rejection, whether thrown at submission (a code-carrying gRPC error) or reported by the result wait,
 * surfaces as a {@link BroadcastError} carrying the platform code where available. A connection failure
 * during submission surfaces as a {@link NetworkError} with `indeterminateDelivery` true, since the bytes
 * may or may not have landed. A failure after submission was acknowledged surfaces as a NetworkError with
 * `indeterminateDelivery` false, the transition was delivered and only its result is unknown. The nonce
 * reads forward to the DAPI client and normalize to bigint. The SDK stays a peer this module never
 * imports; the client is read structurally, inside a boundary that refuses a malformed client at creation.
 */
export function createDashTransport(client: DashSdkClientLike): Transport {
  let platform: DashDapiPlatformLike;
  try {
    if (!client || typeof client.getDAPIClient !== "function") {
      throw new ClientRequiredError("createDashTransport needs a configured dash SDK client");
    }
    platform = client.getDAPIClient().platform;
    if (
      !platform ||
      typeof platform.broadcastStateTransition !== "function" ||
      typeof platform.waitForStateTransitionResult !== "function" ||
      typeof platform.getIdentityNonce !== "function" ||
      typeof platform.getIdentityContractNonce !== "function"
    ) {
      throw new ClientRequiredError("the SDK client's DAPI platform surface is incomplete");
    }
  } catch (e) {
    if (isRawKeySignerError(e)) throw e;
    throw new ClientRequiredError("the SDK client could not be read as a dash SDK client");
  }
  return {
    async broadcast(bytes) {
      // Prepare the owned copy and hash inside a boundary; a hostile byteLength or length on the input
      // subclass throws here, before anything is sent, so delivery is not in question.
      let owned: Uint8Array;
      let hash: Uint8Array;
      let hashHex: string;
      try {
        owned = ownedCopy(bytes);
        hash = ownedCopy(createHash("sha256").update(owned).digest());
        hashHex = toHex(hash);
      } catch (e) {
        if (isRawKeySignerError(e)) throw e;
        throw new NetworkError("the transition bytes could not be prepared for broadcast", { cause: e });
      }
      // Phase 1, submission. A transport-code throw (a timeout, unavailable) leaves delivery unknown; any
      // other code is the platform rejecting at the door; a code-less throw is an indeterminate transport failure.
      try {
        await platform.broadcastStateTransition(owned);
      } catch (e) {
        if (isRawKeySignerError(e)) throw e;
        const code = thrownCode(e);
        if (code !== undefined && !TRANSPORT_CODES.has(code)) {
          throw new BroadcastError("the platform rejected the transition at submission", {
            platformCode: code,
            transitionHash: hashHex,
            cause: e,
          });
        }
        throw new NetworkError("the SDK transport failed while submitting the transition", {
          indeterminateDelivery: true,
          cause: e,
        });
      }
      // Phase 2, the result wait. Submission was acknowledged, so delivery is not in question; a failure
      // here, including a hostile result shape read inside this boundary, leaves only the result unknown.
      let rejection: { code?: number; message?: string } | null;
      try {
        const result = await platform.waitForStateTransitionResult(ownedCopy(hash), { prove: true });
        rejection = readRejection(result);
      } catch (e) {
        if (isRawKeySignerError(e)) throw e;
        throw new NetworkError(
          "the transition was delivered, but waiting for its result failed; check the transition hash on the network",
          { indeterminateDelivery: false, cause: e },
        );
      }
      if (rejection) {
        throw new BroadcastError(`the platform rejected the transition: ${rejection.message ?? "no message"}`, {
          ...(rejection.code !== undefined ? { platformCode: rejection.code } : {}),
          transitionHash: hashHex,
        });
      }
      return { transitionHash: hash, accepted: true };
    },
    async getIdentityNonce(identityId) {
      try {
        const response = await platform.getIdentityNonce(ownedCopy(identityId));
        return nonceToBigint((response as { identityNonce?: unknown } | undefined)?.identityNonce, "identity nonce");
      } catch (e) {
        if (isRawKeySignerError(e)) throw e;
        throw new NetworkError("the SDK transport failed reading the identity nonce", { cause: e });
      }
    },
    async getIdentityContractNonce(identityId, contractId) {
      try {
        const response = await platform.getIdentityContractNonce(ownedCopy(identityId), ownedCopy(contractId));
        return nonceToBigint(
          (response as { identityContractNonce?: unknown } | undefined)?.identityContractNonce,
          "identity contract nonce",
        );
      } catch (e) {
        if (isRawKeySignerError(e)) throw e;
        throw new NetworkError("the SDK transport failed reading the identity contract nonce", { cause: e });
      }
    },
  };
}
