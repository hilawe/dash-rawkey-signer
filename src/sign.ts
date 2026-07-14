/**
 * The general signing path (DESIGN F3, R3). Given an identity snapshot, a raw private key, and an
 * already-constructed transition's bytes, it parses the transition, derives its requirement from the
 * protocol, authorizes and resolves the signing key, signs through the tooling, and returns a
 * library-owned signed transition. The hand-held flows build a transition and then join this same path,
 * so the invariants hold identically (DESIGN R6).
 */
import type { IdentitySnapshot, PrivateKeyInput, SignedTransition } from "./types.js";
import { SecretKey, snapshotPrivateKey } from "./secret.js";
import { authorizeKey, snapshotIdentity, type TransitionDescriptor } from "./authorize.js";
import {
  parseTransition,
  deriveKeyRequirement,
  buildSigningKey,
  signParsed,
  refuseUnauthorizableOnGeneralPath,
  type ParsedTransition,
} from "./adapter/protocol.js";
import { snapshotTransitionBytes } from "./util.js";

/** Sign a caller-supplied, already-constructed transition (the general path). */
export async function signCallerTransition(params: {
  identity: IdentitySnapshot;
  privateKey: PrivateKeyInput;
  transition: Uint8Array;
}): Promise<SignedTransition> {
  // Snapshot every caller-owned input, the transition bytes, the identity, and the private key, before
  // the parse's await, so a concurrent mutation during the gap cannot change what is authorized and
  // signed (the same time-of-check/time-of-use discipline the hand-held flows follow).
  const transition = snapshotTransitionBytes(params.transition, "the transition");
  const identity = snapshotIdentity(params.identity);
  const privateKey = snapshotPrivateKey(params.privateKey);
  try {
    const parsed = await parseTransition(transition);
    refuseUnauthorizableOnGeneralPath(parsed.transitionType);
    return await signParsedTransition(identity, privateKey, parsed);
  } finally {
    if ("raw" in privateKey) privateKey.raw.fill(0);
  }
}

/**
 * Sign an already-parsed transition. Shared by the general path and the hand-held flows, which parse
 * the transition they just built and then sign it here, so a single authorization chokepoint covers
 * every path.
 */
export async function signParsedTransition(
  identity: IdentitySnapshot,
  privateKey: PrivateKeyInput,
  parsed: ParsedTransition,
  override?: { readonly allowedSecurityLevels?: readonly number[] },
): Promise<SignedTransition> {
  const requirement = deriveKeyRequirement(parsed);
  // A hand-held flow with the contract in hand (the documents batch) supplies the contract-tightened
  // security levels, which can only be at least as strict as the protocol default. Every other path
  // uses the requirement derived from the transition and the type table.
  const allowedSecurityLevels = override?.allowedSecurityLevels ?? requirement.allowedSecurityLevels;
  const descriptor: TransitionDescriptor = {
    transitionType: parsed.transitionType,
    authorId: parsed.authorId,
    requiredPurposes: requirement.requiredPurposes,
    allowedSecurityLevels,
  };

  const secret = SecretKey.decode(privateKey, identity.network);
  try {
    const key = authorizeKey(identity, secret.publicKey, descriptor);
    const signingKey = await buildSigningKey(key, identity.protocolVersion);
    const signed = secret.useScalar((scalar) => signParsed(parsed, signingKey, scalar));
    return {
      bytes: signed.bytes,
      transitionType: parsed.transitionType,
      authorId: parsed.authorId,
      signingKeyId: signed.signingKeyId,
      signature: signed.signature,
    };
  } finally {
    secret.dispose();
  }
}
