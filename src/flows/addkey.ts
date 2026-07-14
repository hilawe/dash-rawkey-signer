/**
 * The hand-held add-key flow (DESIGN R2, section 3). It adds a new public key to an identity through an
 * identity-update transition. Two keys take part: the new key signs its own ownership witness (proof of
 * possession), and the identity's master key signs the transition. The flow builds the transition, joins
 * the one authorization step to resolve and bind the master key, signs the witness with the new key, then
 * signs the transition with the master key. Set `nonceContext.identityNonce` and `identity.revision` for
 * offline construction, or configure a transport for the nonce to be read.
 */
import { KeyType } from "../types.js";
import type { IdentitySnapshot, NewKeyInput, NonceContext, PrivateKeyInput, SignedTransition } from "../types.js";
import type { NonceSource } from "../nonce.js";
import { SecretKey } from "../secret.js";
import { authorizeKey, snapshotIdentity } from "../authorize.js";
import {
  constructAddKey,
  signAddKeyWitness,
  deriveKeyRequirement,
  buildSigningKey,
  signParsed,
} from "../adapter/protocol.js";
import { isUint32, isUint64, MAX_UINT64 } from "../util.js";
import { InvalidTransitionError, MissingStateError } from "../errors.js";

export interface SignAddKeyParams {
  readonly identity: IdentitySnapshot;
  /** The master key that signs the transition. Resolved and bound by the authorization step. */
  readonly privateKey: PrivateKeyInput;
  /** The new key to add, carrying its own private key for the ownership witness. */
  readonly newKey: NewKeyInput;
  readonly nonceContext?: NonceContext;
}

export async function signAddKey(
  ctx: { readonly nonceSource: NonceSource | undefined },
  params: SignAddKeyParams,
): Promise<SignedTransition> {
  // Snapshot the identity first (single-read copy, then the copy is validated), so a malformed snapshot
  // surfaces a typed error, an existing key id the tooling would truncate is refused rather than
  // mis-bound, and a changing getter cannot slip a different value past validation.
  const identity = snapshotIdentity(params.identity);
  if (!params.newKey || typeof params.newKey !== "object") {
    throw new InvalidTransitionError("the new key must be an object");
  }

  // Capture the rest of the caller-owned inputs before any await. Numbers are captured by value, and the
  // two private keys are copied into the secret boundary at decode below.
  const newKey = {
    id: params.newKey.id,
    purpose: params.newKey.purpose,
    securityLevel: params.newKey.securityLevel,
    keyType: params.newKey.keyType,
    readOnly: Boolean(params.newKey.readOnly),
  };
  const suppliedNonce = params.nonceContext?.identityNonce;

  if (identity.revision === undefined) {
    throw new MissingStateError("add-key needs the identity's current revision; set identity.revision");
  }
  // Range-check every value before any tooling call: the wasm setters silently wrap out-of-range input,
  // which would sign a value different from what was supplied. Revision needs room for its increment.
  if (!isUint64(identity.revision) || identity.revision >= MAX_UINT64) {
    throw new InvalidTransitionError("the identity revision must be an unsigned 64-bit integer with room to increment");
  }
  if (newKey.keyType !== KeyType.ECDSA_SECP256K1) {
    throw new InvalidTransitionError("add-key supports only ECDSA secp256k1 keys in v1");
  }
  if (!isUint32(newKey.id) || !isUint32(newKey.purpose) || !isUint32(newKey.securityLevel)) {
    throw new InvalidTransitionError("the new key id, purpose, and security level must be unsigned 32-bit integers");
  }
  if (identity.publicKeys.some((key) => key.id === newKey.id)) {
    throw new InvalidTransitionError(`key id ${newKey.id} already exists on the identity`);
  }

  // Nested acquisition so a failure decoding the second secret still zeroes the first (every path zeroes).
  const masterSecret = SecretKey.decode(params.privateKey, identity.network);
  try {
    const newSecret = SecretKey.decode(params.newKey.privateKey, identity.network);
    try {
      let nonce = suppliedNonce;
      if (nonce === undefined) {
        if (ctx.nonceSource === undefined) {
          throw new MissingStateError("add-key needs an identity nonce; supply nonceContext or configure a transport");
        }
        nonce = await ctx.nonceSource.nextIdentityNonce(identity.id);
      }
      if (!isUint64(nonce, 1n)) {
        throw new InvalidTransitionError("the identity nonce must be an unsigned 64-bit integer at least 1");
      }

      // Build the transition with the new key's public bytes (derived inside the secret boundary).
      const { parsed, witnessKey } = await constructAddKey({
        snapshot: identity,
        nonce,
        newKey: { ...newKey, publicData: newSecret.publicKey },
      });

      // The one authorization chokepoint resolves and binds the master key against the transition's own
      // requirement (identity update needs a master key). A non-master key fails closed here.
      const requirement = deriveKeyRequirement(parsed);
      const masterKey = authorizeKey(identity, masterSecret.publicKey, {
        transitionType: parsed.transitionType,
        authorId: parsed.authorId,
        requiredPurposes: requirement.requiredPurposes,
        allowedSecurityLevels: requirement.allowedSecurityLevels,
      });

      // The new key signs its ownership witness (with the resolved master key id set), then the master key
      // signs the transition. Both scalars stay inside the secret boundary and are zeroed in the finally.
      newSecret.useScalar((scalar) => signAddKeyWitness(parsed, witnessKey, masterKey.id, newKey.keyType, scalar));
      const signingKey = await buildSigningKey(masterKey, identity.protocolVersion);
      const signed = masterSecret.useScalar((scalar) => signParsed(parsed, signingKey, scalar));
      return {
        bytes: signed.bytes,
        transitionType: parsed.transitionType,
        authorId: parsed.authorId,
        signingKeyId: signed.signingKeyId,
        signature: signed.signature,
      };
    } finally {
      newSecret.dispose();
    }
  } finally {
    masterSecret.dispose();
  }
}
