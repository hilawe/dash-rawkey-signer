/** Small internal byte and input helpers. No dependency on the tooling. */
// errors.ts imports nothing back, so this import creates no cycle.
import { InvalidTransitionError } from "./errors.js";

/** Constant-time-ish byte equality. Length check first, then compare every byte. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Lowercase hex, for human-readable identifiers in error messages (never key material). */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

/**
 * The protocol's integer widths. The tooling's WebAssembly setters silently wrap out-of-range values, so
 * inputs are range-checked against these before any tooling call. Key ids are unsigned 32-bit; nonces,
 * revisions, and credit amounts are unsigned 64-bit.
 */
export const MAX_UINT32 = 0xffffffff;
export const MAX_UINT64 = 2n ** 64n - 1n;

/** True when `value` is an integer in the unsigned 32-bit range (a valid protocol key id). */
export function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32;
}

/** True when `value` is a bigint in `[min, MAX_UINT64]` (a valid protocol nonce, revision, or amount). */
export function isUint64(value: bigint, min = 0n): boolean {
  return typeof value === "bigint" && value >= min && value <= MAX_UINT64;
}

/**
 * A description of a value for an error message that never throws. A hostile object with a throwing
 * `Symbol.toPrimitive` would make template interpolation or `String(value)` throw a native error, which
 * must not happen while building a typed error's message. Primitives (including symbols, via the function
 * form of `String`) coerce safely, and an object or function is described by its `typeof` alone, so no
 * user-defined coercion runs.
 */
export function describeType(value: unknown): string {
  const t = typeof value;
  return t === "object" || t === "function" ? t : String(value);
}

/**
 * Guard and copy caller-supplied transition bytes in one step, before any await (the time-of-check/
 * time-of-use discipline). Every public entry that accepts raw transition bytes goes through this, so the
 * rule is enforced by construction rather than by vigilance at each site. A non-array input and a byte
 * view whose read throws both surface the typed transition error, with the caller's context leading the
 * message.
 */
export function snapshotTransitionBytes(input: unknown, context: string): Uint8Array {
  if (!(input instanceof Uint8Array)) {
    throw new InvalidTransitionError(`${context} must be a Uint8Array of serialized transition bytes`);
  }
  try {
    const copy = new Uint8Array(input.byteLength);
    copy.set(input);
    return copy;
  } catch {
    throw new InvalidTransitionError(`${context} bytes could not be read`);
  }
}
