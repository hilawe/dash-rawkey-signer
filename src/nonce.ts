/**
 * The nonce source (DESIGN section 10, decision D2). An injectable seam so a cross-process lease can be
 * added later without a breaking change. The default reads the current nonce through the transport and
 * hands out sequential values, serializing allocation within the process so two concurrent sign calls
 * receive distinct successive nonces rather than racing for the same one. Cross-process conflicts still
 * surface at broadcast as a NonceConflictError for the caller to retry.
 */
import type { Transport } from "./adapter/transport.js";
import { toHex } from "./util.js";
import { guard, InvalidTransitionError } from "./errors.js";

export interface NonceSource {
  nextIdentityNonce(identityId: Uint8Array): Promise<bigint>;
  nextIdentityContractNonce(identityId: Uint8Array, contractId: Uint8Array): Promise<bigint>;
}

/**
 * The default nonce source. Per scope it chains allocations so they serialize, and each allocation both
 * re-reads the current network nonce (to follow other processes) and stays strictly above the last
 * value handed out in this process (to avoid an in-process collision).
 */
export function createDefaultNonceSource(transport: Transport): NonceSource {
  const lastAllocated = new Map<string, Promise<bigint>>();

  function allocate(scope: string, fetchCurrent: () => Promise<bigint>): Promise<bigint> {
    const previous = lastAllocated.get(scope) ?? Promise.resolve(-1n);
    const next = (async (): Promise<bigint> => {
      const prior = await previous.catch(() => -1n);
      const current = await fetchCurrent();
      // A transport that returns a non-bigint would make the arithmetic below throw a native TypeError; fail
      // with a typed error instead, so this source upholds the same boundary as the signer's methods.
      if (typeof current !== "bigint") {
        throw new InvalidTransitionError("the transport returned a non-bigint nonce");
      }
      const fromNetwork = current + 1n;
      return fromNetwork > prior ? fromNetwork : prior + 1n;
    })();
    lastAllocated.set(scope, next);
    return next;
  }

  // Guard both methods, so this source surfaces a typed error even when called directly (a proxied
  // identifier that throws in toHex, a misbehaving transport) rather than a native throw or a raw rejection.
  return {
    nextIdentityNonce: (identityId) =>
      guard(() => allocate(`i:${toHex(identityId)}`, () => transport.getIdentityNonce(identityId))),
    nextIdentityContractNonce: (identityId, contractId) =>
      guard(() =>
        allocate(`c:${toHex(identityId)}:${toHex(contractId)}`, () =>
          transport.getIdentityContractNonce(identityId, contractId),
        ),
      ),
  };
}
