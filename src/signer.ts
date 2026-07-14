/**
 * The public entry point (DESIGN section 3). `createRawKeySigner` returns a signer that holds transport
 * and network configuration but never a private key. Every operation takes the identity and the raw key,
 * so no long-lived object owns a secret. An optional bound view (`withKey`) carries one key for the
 * common single-key flow.
 */
import type {
  AuthorizedKeyInfo,
  IdentitySnapshot,
  Network,
  PrivateKeyInput,
  SignedTransition,
  SubmissionResult,
} from "./types.js";
import { NETWORKS } from "./types.js";
import type { Transport } from "./adapter/transport.js";
import type { NonceSource } from "./nonce.js";
import { createDefaultNonceSource } from "./nonce.js";
import { SecretKey, assertPrivateKeyShape, snapshotPrivateKey } from "./secret.js";
import { authorizeKey, snapshotIdentity } from "./authorize.js";
import { parseTransition, deriveKeyRequirement, refuseUnauthorizableOnGeneralPath } from "./adapter/protocol.js";
import { signCallerTransition } from "./sign.js";
import { signWithdrawal as signWithdrawalFlow, type SignWithdrawalParams } from "./flows/withdrawal.js";
import { signDocumentBatch as signDocumentBatchFlow, type SignDocumentBatchParams } from "./flows/documents.js";
import { signAddKey as signAddKeyFlow, type SignAddKeyParams } from "./flows/addkey.js";
import {
  ClientRequiredError,
  InvalidIdentitySnapshotError,
  guard,
  guardSync,
  InvalidTransitionError,
  MissingStateError,
} from "./errors.js";
import { snapshotTransitionBytes } from "./util.js";

export interface RawKeySignerOptions {
  readonly network: Network;
  /** Injected transport for reads and broadcast. Required only for the online flows and `broadcast`. */
  readonly transport?: Transport;
  /** Injected nonce source. Defaults to an in-process-reserving source over the transport. */
  readonly nonceSource?: NonceSource;
}

/** A signer bound to one raw key for repeated operations on the common single-key flow (decision D5). */
export interface BoundSigner {
  signTransition(params: { identity: IdentitySnapshot; transition: Uint8Array }): Promise<SignedTransition>;
  authorize(params: { identity: IdentitySnapshot; transition: Uint8Array }): Promise<AuthorizedKeyInfo>;
  /** Zero any raw key bytes this view holds and mark it unusable. */
  dispose(): void;
}

export interface RawKeySigner {
  /** Sign a caller-supplied, already-constructed transition (the general path, R3). */
  signTransition(params: {
    identity: IdentitySnapshot;
    privateKey: PrivateKeyInput;
    transition: Uint8Array;
  }): Promise<SignedTransition>;

  /** Hand-held documents-batch flow (R2, D4). Builds the batch, then joins the one signing path. */
  signDocumentBatch(params: SignDocumentBatchParams): Promise<SignedTransition>;

  /** Hand-held credit-withdrawal flow (R2). Constructs, then joins the one signing path. */
  signWithdrawal(params: SignWithdrawalParams): Promise<SignedTransition>;

  /** Hand-held add-key flow (R2). The new key signs its witness, the master key signs the transition. */
  signAddKey(params: SignAddKeyParams): Promise<SignedTransition>;

  /** Read-only possession and authorization check. Resolves the key that would sign, and unlocks nothing. */
  authorize(params: {
    identity: IdentitySnapshot;
    privateKey: PrivateKeyInput;
    transition: Uint8Array;
  }): Promise<AuthorizedKeyInfo>;

  /** Parse and validate a signed transition, then broadcast it. Never transmits unparseable bytes. */
  broadcast(signed: SignedTransition | Uint8Array): Promise<SubmissionResult>;

  /** A bound view carrying one raw key. */
  withKey(privateKey: PrivateKeyInput): BoundSigner;
}

async function authorizeOnly(
  identity: IdentitySnapshot,
  privateKey: PrivateKeyInput,
  transition: Uint8Array,
): Promise<AuthorizedKeyInfo> {
  // Snapshot the transition bytes, the identity, and the key before the parse's await, so a concurrent
  // mutation during the gap cannot change what is authorized (the same discipline as the signing paths).
  const transitionSnap = snapshotTransitionBytes(transition, "the transition");
  const identitySnap = snapshotIdentity(identity);
  const keySnap = snapshotPrivateKey(privateKey);
  try {
    const parsed = await parseTransition(transitionSnap);
    refuseUnauthorizableOnGeneralPath(parsed.transitionType);
    const requirement = deriveKeyRequirement(parsed);
    const secret = SecretKey.decode(keySnap, identitySnap.network);
    try {
      const key = authorizeKey(identitySnap, secret.publicKey, {
        transitionType: parsed.transitionType,
        authorId: parsed.authorId,
        requiredPurposes: requirement.requiredPurposes,
        allowedSecurityLevels: requirement.allowedSecurityLevels,
      });
      return { keyId: key.id, purpose: key.purpose, securityLevel: key.securityLevel };
    } finally {
      secret.dispose();
    }
  } finally {
    if ("raw" in keySnap) keySnap.raw.fill(0);
  }
}

export function createRawKeySigner(options: RawKeySignerOptions): RawKeySigner {
  // Validate the options at the one construction boundary, inside guardSync so even a hostile options proxy
  // yields a typed error rather than a native throw from a property read. A null options object or an
  // unknown network is the realistic case and gets a precise message.
  return guardSync(() => buildSigner(options));
}

function buildSigner(options: RawKeySignerOptions): RawKeySigner {
  if (!options || typeof options !== "object") {
    throw new MissingStateError("a signer requires an options object with a network");
  }
  // Validate against the supported set derived from the Network type, so this check cannot drift from the
  // type as networks are added (a local devnet is a supported network and uses testnet key encoding).
  if (!NETWORKS.includes(options.network)) {
    throw new MissingStateError(`a signer requires a network of ${NETWORKS.map((n) => `'${n}'`).join(", ")}`);
  }
  const nonceSource: NonceSource | undefined =
    options.nonceSource ?? (options.transport ? createDefaultNonceSource(options.transport) : undefined);

  // The signer's configured network is an enforcement boundary, not advisory configuration. Every
  // key-bearing operation checks the identity's network against it, so a testnet-configured signer cannot
  // sign a mainnet snapshot (a holistic-review finding: the option was validated, then never enforced).
  // The read is guarded; a malformed snapshot falls through to the flow's own validator for its precise
  // error. Broadcast takes only bytes, which carry no network for the library to check, a documented limit.
  const expectNetwork = <P extends { identity?: unknown }>(params: P): P => {
    let network: unknown;
    try {
      network = (params?.identity as { network?: unknown } | undefined)?.network;
    } catch {
      return params;
    }
    if (network !== undefined && network !== options.network) {
      throw new InvalidIdentitySnapshotError(
        `the identity snapshot is for network '${String(network)}', but this signer is configured for '${options.network}'`,
      );
    }
    return params;
  };

  const signer: RawKeySigner = {
    signTransition: (params) => guard(() => signCallerTransition(expectNetwork(params))),

    signDocumentBatch: (params) => guard(() => signDocumentBatchFlow({ nonceSource }, expectNetwork(params))),

    signWithdrawal: (params) => guard(() => signWithdrawalFlow({ nonceSource }, expectNetwork(params))),

    signAddKey: (params) => guard(() => signAddKeyFlow({ nonceSource }, expectNetwork(params))),

    authorize: (params) => guard(() => authorizeOnly(expectNetwork(params).identity, params.privateKey, params.transition)),

    broadcast: (signed) =>
      guard(async () => {
        // A precise typed error for a missing or shapeless input, rather than letting the boundary net
        // wrap the native property-read TypeError as an UnexpectedError.
        const bytes =
          signed instanceof Uint8Array ? signed : signed && typeof signed === "object" ? signed.bytes : undefined;
        if (!(bytes instanceof Uint8Array)) {
          throw new InvalidTransitionError(
            "broadcast input must be a SignedTransition or a Uint8Array of transition bytes",
          );
        }
        // Snapshot before the parse's await, so what was validated is exactly what is transmitted; a
        // caller-held reference mutated during the gap cannot make the parse see one version and the
        // transport send another.
        const owned = snapshotTransitionBytes(bytes, "broadcast input");
        // Parse before transport so a stray or non-transition byte array is rejected, not transmitted.
        try {
          await parseTransition(owned);
        } catch {
          throw new InvalidTransitionError("broadcast input is not a parseable state transition");
        }
        if (options.transport === undefined) {
          throw new ClientRequiredError("broadcast requires a transport, none was configured");
        }
        return options.transport.broadcast(owned);
      }),

    withKey(privateKey) {
      // Validate the key's shape at bind time, inside guardSync so a malformed key is a typed error here
      // (a precise InvalidPrivateKeyError for the ordinary case, or the catch-all for a hostile proxy)
      // rather than a native throw. The view holds the caller's key by reference and dispose zeroes its raw
      // bytes, one buffer scrubbed rather than a lingering second copy.
      return guardSync(() => {
        assertPrivateKeyShape(privateKey);
        let held: PrivateKeyInput | null = privateKey;
        const use = (): PrivateKeyInput => {
          if (held === null) throw new ClientRequiredError("this bound signer has been disposed");
          return held;
        };
        return {
          signTransition: (params) =>
            guard(() =>
              signCallerTransition({ identity: expectNetwork(params).identity, privateKey: use(), transition: params.transition }),
            ),
          authorize: (params) => guard(() => authorizeOnly(expectNetwork(params).identity, use(), params.transition)),
          dispose() {
            // Best-effort zeroing that never throws, even if the caller's key is an object whose `fill` was
            // overridden to throw. The view is marked unusable regardless.
            try {
              if (held !== null && "raw" in held) held.raw.fill(0);
            } catch {
              // ignore: dispose is best-effort cleanup, not a failable operation
            }
            held = null;
          },
        };
      });
    },
  };

  return signer;
}
