/**
 * The transport side of the adapter (DESIGN section 7). The library does not own a network client. The
 * caller injects a transport, typically a thin wrapper over their `dash` SDK client, and the library
 * uses it for the reads and the broadcast the online flows need. Everything crosses this boundary as
 * bytes and plain values, so no tooling object is exchanged.
 */
import type { SubmissionResult } from "../types.js";

export interface Transport {
  /** Broadcast a serialized, signed state transition and report the outcome. */
  broadcast(signedTransition: Uint8Array): Promise<SubmissionResult>;
  /** The identity's current identity-level nonce. */
  getIdentityNonce(identityId: Uint8Array): Promise<bigint>;
  /** The identity's current nonce for a given data contract. */
  getIdentityContractNonce(identityId: Uint8Array, contractId: Uint8Array): Promise<bigint>;
}
