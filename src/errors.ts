/**
 * The typed error hierarchy (DESIGN section 6, requirement R11).
 *
 * Every failure a caller can branch on extends {@link RawKeySignerError} and carries a stable `code`.
 * Callers branch by `instanceof` or by `code`. Message text is human-readable and is not part of the
 * compatibility promise. Errors never carry private key material, only identifiers (R5).
 */

/** A stable, machine-branchable code for each error type. */
export type RawKeySignerErrorCode =
  | "INVALID_PRIVATE_KEY"
  | "INVALID_IDENTITY_SNAPSHOT"
  | "INVALID_TRANSITION"
  | "UNSUPPORTED_TRANSITION_TYPE"
  | "AUTHOR_IDENTITY_MISMATCH"
  | "KEY_NOT_ON_IDENTITY"
  | "DECLARED_SIGNING_KEY_MISMATCH"
  | "KEY_PURPOSE_MISMATCH"
  | "KEY_SECURITY_LEVEL_MISMATCH"
  | "KEY_DISABLED"
  | "MISSING_STATE"
  | "INVALID_CORE_FEE_RATE"
  | "INSUFFICIENT_BALANCE"
  | "CLIENT_REQUIRED"
  | "NONCE_CONFLICT"
  | "BROADCAST_ERROR"
  | "NETWORK_ERROR"
  | "UNEXPECTED_ERROR";

/**
 * A brand for errors constructed through this library's error classes. `instanceof` can be forged by a
 * proxy whose `getPrototypeOf` reports our prototype, which would let a plain caller object (possibly
 * holding a key buffer) pass classification and be rethrown unchanged. WeakSet membership is identity-based,
 * invokes no proxy trap, and cannot be forged, so a foreign object or proxy is never recognized.
 *
 * The brand certifies construction through our classes, not that library code (rather than caller code)
 * threw the error. A caller can construct one of these classes directly, and such an instance is
 * recognized and relayed. That is an accepted boundary (R5, DESIGN section 6): the library never attaches
 * key material to an error it builds, so any key on a relayed error was put there by the caller's own code,
 * the same trust already extended to a caller-supplied transport's error contents. See the README security
 * model for the boundary a caller must respect.
 */
const SIGNER_ERRORS = new WeakSet<object>();

/** Base class for every error this library throws. */
export abstract class RawKeySignerError extends Error {
  abstract readonly code: RawKeySignerErrorCode;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    // Preserve the concrete subclass name across transpilation and V8.
    this.name = new.target.name;
    SIGNER_ERRORS.add(this);
  }
}

// --- Authorization and binding (DESIGN section 4) ---

/** The supplied key could not be decoded as a WIF string or raw 32-byte value. */
export class InvalidPrivateKeyError extends RawKeySignerError {
  readonly code = "INVALID_PRIVATE_KEY";
}

/**
 * The supplied identity snapshot is malformed, for example a key with a non-integer or duplicate id,
 * which would make key resolution non-deterministic. Snapshots assembled directly by a caller are
 * validated (DESIGN section 3, decision D1), not only those built by the adapter.
 */
export class InvalidIdentitySnapshotError extends RawKeySignerError {
  readonly code = "INVALID_IDENTITY_SNAPSHOT";
}

/** A transition could not be parsed or described by the tooling (fail closed). */
export class InvalidTransitionError extends RawKeySignerError {
  readonly code = "INVALID_TRANSITION";
}

/**
 * No authoritative key requirement could be derived for the transition, so the library refuses to
 * sign rather than sign on a weaker check (DESIGN F2, F3).
 */
export class UnsupportedTransitionTypeError extends RawKeySignerError {
  readonly code = "UNSUPPORTED_TRANSITION_TYPE";
  readonly transitionType: number | undefined;
  constructor(message: string, transitionType?: number) {
    super(message);
    this.transitionType = transitionType;
  }
}

/** The transition is authored by a different identity than the one supplied. */
export class AuthorIdentityMismatchError extends RawKeySignerError {
  readonly code = "AUTHOR_IDENTITY_MISMATCH";
  readonly expectedIdentityId: string;
  readonly transitionAuthorId: string;
  constructor(expectedIdentityId: string, transitionAuthorId: string) {
    super(
      `transition is authored by ${transitionAuthorId}, not the supplied identity ${expectedIdentityId}`,
    );
    this.expectedIdentityId = expectedIdentityId;
    this.transitionAuthorId = transitionAuthorId;
  }
}

/** The supplied key's public bytes match no registered key on the identity. */
export class KeyNotOnIdentityError extends RawKeySignerError {
  readonly code = "KEY_NOT_ON_IDENTITY";
}

/**
 * A caller-supplied transition declares a signing-key id that is not registered on the identity with
 * the supplied key's public bytes. The transition names one key while being signed by another.
 */
export class DeclaredSigningKeyMismatchError extends RawKeySignerError {
  readonly code = "DECLARED_SIGNING_KEY_MISMATCH";
  readonly declaredKeyId: number;
  constructor(declaredKeyId: number) {
    super(
      `the transition declares signing-key id ${declaredKeyId}, which is not a key on the identity matching the supplied private key`,
    );
    this.declaredKeyId = declaredKeyId;
  }
}

/** The matched key does not carry the purpose the transition requires. */
export class KeyPurposeMismatchError extends RawKeySignerError {
  readonly code = "KEY_PURPOSE_MISMATCH";
  readonly keyId: number;
  readonly actualPurpose: number;
  readonly requiredPurpose: readonly number[];
  readonly transitionType: number;
  constructor(keyId: number, actualPurpose: number, requiredPurpose: readonly number[], transitionType: number) {
    super(
      `key ${keyId} has purpose ${actualPurpose}, but transition type ${transitionType} requires one of ${requiredPurpose.join(", ")}`,
    );
    this.keyId = keyId;
    this.actualPurpose = actualPurpose;
    this.requiredPurpose = requiredPurpose;
    this.transitionType = transitionType;
  }
}

/** The matched key's security level does not meet the transition's requirement. */
export class KeySecurityLevelMismatchError extends RawKeySignerError {
  readonly code = "KEY_SECURITY_LEVEL_MISMATCH";
  readonly keyId: number;
  readonly actualSecurityLevel: number;
  readonly requiredSecurityLevel: readonly number[];
  readonly transitionType: number;
  constructor(
    keyId: number,
    actualSecurityLevel: number,
    requiredSecurityLevel: readonly number[],
    transitionType: number,
  ) {
    super(
      `key ${keyId} has security level ${actualSecurityLevel}, but transition type ${transitionType} requires one of ${requiredSecurityLevel.join(", ")}`,
    );
    this.keyId = keyId;
    this.actualSecurityLevel = actualSecurityLevel;
    this.requiredSecurityLevel = requiredSecurityLevel;
    this.transitionType = transitionType;
  }
}

/** The matched key is disabled on the identity. */
export class KeyDisabledError extends RawKeySignerError {
  readonly code = "KEY_DISABLED";
  readonly keyId: number;
  constructor(keyId: number) {
    super(`key ${keyId} is disabled on the identity`);
    this.keyId = keyId;
  }
}

// --- Construction and state ---

/** Offline construction or a signing path lacked a required piece of state (DESIGN section 8). */
export class MissingStateError extends RawKeySignerError {
  readonly code = "MISSING_STATE";
}

/** A credit withdrawal's core fee rate was zero, below the floor, or not in the allowed sequence. */
export class InvalidCoreFeeRateError extends RawKeySignerError {
  readonly code = "INVALID_CORE_FEE_RATE";
  readonly rate: number;
  constructor(rate: number, reason: string) {
    super(`core fee rate ${rate} is invalid: ${reason}`);
    this.rate = rate;
  }
}

/** The identity's credit balance is insufficient for the operation. */
export class InsufficientBalanceError extends RawKeySignerError {
  readonly code = "INSUFFICIENT_BALANCE";
  readonly required: bigint;
  readonly available: bigint;
  constructor(required: bigint, available: bigint) {
    super(`operation requires ${required} credits but the identity has ${available}`);
    this.required = required;
    this.available = available;
  }
}

/** A nonce acquisition or a broadcast was attempted without a configured transport. */
export class ClientRequiredError extends RawKeySignerError {
  readonly code = "CLIENT_REQUIRED";
}

// --- Network and submission ---

/**
 * A supplied nonce conflicted with the network's current value. Surfaced at submission, not
 * construction (DESIGN sections 6 and 10). Carries the observed nonce so the caller can retry.
 */
export class NonceConflictError extends RawKeySignerError {
  readonly code = "NONCE_CONFLICT";
  readonly observedNonce: bigint | undefined;
  constructor(message: string, observedNonce?: bigint) {
    super(message);
    this.observedNonce = observedNonce;
  }
}

/** The network rejected the broadcast of a state transition. */
export class BroadcastError extends RawKeySignerError {
  readonly code = "BROADCAST_ERROR";
  readonly retryable: boolean;
  readonly platformCode: number | undefined;
  readonly transitionHash: string | undefined;
  constructor(
    message: string,
    details?: { retryable?: boolean; platformCode?: number; transitionHash?: string; cause?: unknown },
  ) {
    super(message, details?.cause !== undefined ? { cause: details.cause } : undefined);
    this.retryable = details?.retryable ?? false;
    this.platformCode = details?.platformCode;
    this.transitionHash = details?.transitionHash;
  }
}

/** A transport-level failure, including an indeterminate delivery after a submission timeout. */
export class NetworkError extends RawKeySignerError {
  readonly code = "NETWORK_ERROR";
  readonly indeterminateDelivery: boolean;
  constructor(message: string, options?: { indeterminateDelivery?: boolean; cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.indeterminateDelivery = options?.indeterminateDelivery ?? false;
  }
}

// --- The typed-error boundary (R11) ---

/**
 * A failure a caller can still branch on (it extends {@link RawKeySignerError}) that the specific guards
 * did not anticipate, for example a tooling exception or a native error from adversarially-malformed input
 * such as a `Uint8Array` subclass with a throwing iterator. The specific errors above fire first for
 * recognized bad input, and this is the catch-all a public method translates any other throw into, so no
 * native error or raw string ever escapes the library boundary.
 *
 * The thrown value is deliberately not retained. Code the caller controls (a hostile iterator, a getter)
 * can throw an object that references the caller's own key buffer, and an error is often logged, so keeping
 * the value would breach the invariant that an error never carries key material (R5). Only `typeof` the
 * value is recorded, which reads no property and invokes no proxy trap, so it can neither leak the key nor
 * throw during construction.
 */
export class UnexpectedError extends RawKeySignerError {
  readonly code = "UNEXPECTED_ERROR";
  readonly thrownType: string;
  constructor(thrown?: unknown) {
    const thrownType = typeof thrown;
    super(`an unexpected ${thrown === undefined ? "error" : `${thrownType} value`} was raised while processing the request`);
    this.thrownType = thrownType;
  }
}

/**
 * Test whether a value was constructed through this library's error classes, by non-spoofable brand rather
 * than `instanceof`. It never throws (WeakSet membership invokes no proxy trap) and cannot be forged by a
 * proxy that reports our prototype, so a foreign object never passes classification. It does not distinguish
 * a library-thrown instance from one a caller constructed directly (see {@link RawKeySignerError}'s brand).
 *
 * One accepted limit: the brand is per-module-instance, so if a dependency tree loads two copies of this
 * library, an error from one copy fails the other's check and is re-wrapped as an {@link UnexpectedError}.
 * That degrades safely, the caller still receives a typed error, just a less specific one, and the
 * alternative of a forgeable marker property would reopen the spoofing hole this brand closes.
 */
export function isRawKeySignerError(value: unknown): value is RawKeySignerError {
  return typeof value === "object" && value !== null && SIGNER_ERRORS.has(value);
}

/**
 * Translate any thrown value into a typed error. A {@link RawKeySignerError} passes through unchanged, so
 * the specific typed errors keep their type and fields, and anything else becomes an {@link UnexpectedError}.
 * A public method runs its body through this, which is what makes the typed-error invariant hold for every
 * input, the exotic long tail included, without a try/catch at each individual operation. It never throws.
 */
export function toRawKeySignerError(value: unknown): RawKeySignerError {
  return isRawKeySignerError(value) ? value : new UnexpectedError(value);
}

/**
 * Run an async operation at a public boundary so any value it throws that is not already a
 * {@link RawKeySignerError} surfaces as a typed one. The specific guards in the flows, the adapter, and the
 * secret boundary fire first for recognized bad input, giving a precise type; this is the catch-all that
 * closes the exotic long tail without a try/catch at each operation. `toRawKeySignerError` never throws, so
 * the guard cannot itself leak while classifying.
 */
export async function guard<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op();
  } catch (e) {
    throw toRawKeySignerError(e);
  }
}

/** The synchronous counterpart, for a public entry that returns a value rather than a promise. */
export function guardSync<T>(op: () => T): T {
  try {
    return op();
  } catch (e) {
    throw toRawKeySignerError(e);
  }
}
