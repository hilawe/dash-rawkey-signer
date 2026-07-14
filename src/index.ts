/**
 * dash-rawkey-signer. Sign Dash Platform state transitions as an identity using a raw private key,
 * with no hierarchical-deterministic wallet seed.
 *
 * The public surface is library-owned (DESIGN decision D1). See DESIGN.md for the full design.
 */
export * from "./errors.js";
export * from "./types.js";
export { createRawKeySigner } from "./signer.js";
export { validateIdentitySnapshot, snapshotIdentity } from "./authorize.js";
/**
 * Load the protocol WebAssembly ahead of the first operation. Optional: every operation loads it lazily
 * on demand, but instantiation blocks the event loop noticeably once, so a backend service can take that
 * hit at startup instead of on its first live request.
 */
export { ensureLoaded as initialize } from "./adapter/protocol.js";
export type { RawKeySigner, RawKeySignerOptions, BoundSigner } from "./signer.js";
export type { Transport } from "./adapter/transport.js";
export { createDefaultNonceSource } from "./nonce.js";
export type { NonceSource } from "./nonce.js";
export { snapshotFromDashIdentity } from "./integration.js";
export type { DashIdentityLike, DashIdentityKeyLike, SnapshotOptions } from "./integration.js";
