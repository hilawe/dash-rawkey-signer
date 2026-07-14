/**
 * The secret boundary (DESIGN section 5, requirement R5). A raw private key enters only here, is held as
 * a single owned buffer, is exposed only to a signing callback, and is zeroed on dispose. Decode errors
 * are sanitized so a bad WIF or key bytes never appear in an error. The honest limits: copies the tooling
 * makes cannot be erased, which covers opaque WebAssembly internals, the dashcore PrivateKey's internal
 * big-number representation (garbage-collected, not zeroable), and the immutable strings a decode passes
 * through (a caller's WIF, and the hex encoding of raw bytes). What this module controls, it zeroes, its
 * own scalar buffer and every intermediate byte buffer it receives. Callers handling long-lived secrets
 * should prefer raw bytes.
 */
import { createRequire } from "node:module";
import type * as Dashcore from "@dashevo/dashcore-lib";
import type { Network, PrivateKeyInput } from "./types.js";
import { InvalidPrivateKeyError } from "./errors.js";
import { toHex } from "./util.js";

// dashcore-lib is CommonJS and, under an ESM consumer, exposes its classes only through the default
// export, so it is loaded through require while its types come from the type-only import above.
const nodeRequire = createRequire(import.meta.url);
const { PrivateKey } = nodeRequire("@dashevo/dashcore-lib") as typeof Dashcore;

/** Map the library network to a dashcore network for key encoding. Local devnets use testnet encoding. */
function coreNetwork(network: Network): "livenet" | "testnet" {
  return network === "mainnet" ? "livenet" : "testnet";
}

/**
 * Structurally validate a private-key input, throwing a typed {@link InvalidPrivateKeyError} on a malformed
 * shape, without copying. Used where the key is held by reference (the bound view) rather than snapshotted,
 * so a later dispose or decode cannot throw a native error on a non-conforming object (DESIGN R11). The raw
 * bytes are not validated as a key here, that happens at {@link SecretKey.decode}; this only guards the shape.
 */
export function assertPrivateKeyShape(input: PrivateKeyInput): void {
  if (!input || typeof input !== "object") {
    throw new InvalidPrivateKeyError("the private key must be an object with raw bytes or a wif string");
  }
  if ("raw" in input) {
    if (!(input.raw instanceof Uint8Array)) {
      throw new InvalidPrivateKeyError("a raw private key must be a Uint8Array");
    }
    return;
  }
  if ("wif" in input && typeof input.wif === "string") {
    return;
  }
  throw new InvalidPrivateKeyError("the private key must be { raw: Uint8Array } or { wif: string }");
}

/**
 * Structurally validate a private-key input and return an owned copy, for a flow that snapshots the key
 * before an await. A malformed input surfaces a typed {@link InvalidPrivateKeyError} rather than a native
 * TypeError from a later clone (DESIGN R11).
 */
export function snapshotPrivateKey(input: PrivateKeyInput): PrivateKeyInput {
  assertPrivateKeyShape(input);
  if ("raw" in input) {
    try {
      return { raw: Uint8Array.from(input.raw) };
    } catch {
      throw new InvalidPrivateKeyError("the raw private key bytes could not be read");
    }
  }
  return { wif: input.wif };
}

export class SecretKey {
  #scalar: Uint8Array | null;
  /** The derived compressed public key bytes, safe to expose and used to match the identity's keys. */
  readonly publicKey: Uint8Array;

  private constructor(scalar: Uint8Array, publicKey: Uint8Array) {
    this.#scalar = scalar;
    this.publicKey = publicKey;
  }

  /**
   * Decode a caller-supplied private key. Never reads the environment or files. On any decode failure
   * throws {@link InvalidPrivateKeyError} with no `cause`, so the input value cannot leak.
   */
  static decode(input: PrivateKeyInput, network: Network): SecretKey {
    const net = coreNetwork(network);
    let priv: Dashcore.PrivateKey;
    try {
      if ("wif" in input) {
        if (typeof input.wif !== "string" || input.wif.length === 0) {
          throw new InvalidPrivateKeyError("a WIF private key must be a non-empty string");
        }
        priv = new PrivateKey(input.wif, net);
      } else {
        if (!(input.raw instanceof Uint8Array) || input.raw.length !== 32) {
          throw new InvalidPrivateKeyError("a raw private key must be exactly 32 bytes");
        }
        // A 64-character hex scalar is classified as a private key and yields a compressed key.
        priv = new PrivateKey(toHex(input.raw), net);
      }
    } catch (e) {
      if (e instanceof InvalidPrivateKeyError) throw e;
      throw new InvalidPrivateKeyError("the supplied private key could not be decoded");
    }
    // BN.toBuffer with a fixed size (left-padded to 32 bytes) is present at runtime but absent from the
    // dashcore-lib BN typings, so its shape is asserted narrowly here.
    const bn = priv.bn as unknown as { toBuffer(opts: { size: number }): Buffer };
    // Copy the scalar into an owned allocation and zero the intermediate. toBuffer returns a fresh Buffer
    // (typically from Node's pooled slab); without the explicit fill, that copy would fall to the garbage
    // collector still holding the key, out of reach of dispose (R5). Any throw in this tail zeroes the
    // owned scalar too and surfaces the sanitized typed error, so no path abandons key bytes unzeroed and
    // no tooling error escapes untyped.
    const scalar = new Uint8Array(32);
    let intermediate: Buffer | null = null;
    try {
      intermediate = bn.toBuffer({ size: 32 });
      scalar.set(intermediate);
      const publicKey = Uint8Array.from(priv.toPublicKey().toBuffer() as Buffer);
      return new SecretKey(scalar, publicKey);
    } catch {
      scalar.fill(0);
      throw new InvalidPrivateKeyError("the supplied private key could not be decoded");
    } finally {
      // Best-effort cleanup that never throws: a throw here would replace the pending typed error (or a
      // successful return) with an untyped one. If a hostile fill refuses to zero, nothing more can be done.
      try {
        if (intermediate) intermediate.fill(0);
      } catch {
        // ignore: cleanup is best-effort
      }
    }
  }

  /**
   * Provide the raw scalar to a signing callback for the moment of signing. The buffer view shares the
   * owned bytes, so {@link dispose} zeroes exactly what the callback saw. Throws if already disposed.
   */
  useScalar<T>(fn: (scalar: Buffer) => T): T {
    if (this.#scalar === null) {
      throw new InvalidPrivateKeyError("the secret key has already been disposed");
    }
    const view = Buffer.from(this.#scalar.buffer, this.#scalar.byteOffset, this.#scalar.byteLength);
    return fn(view);
  }

  /** Best-effort zeroing of the owned scalar, and mark the key unusable. Idempotent. */
  dispose(): void {
    if (this.#scalar !== null) {
      this.#scalar.fill(0);
      this.#scalar = null;
    }
  }
}
