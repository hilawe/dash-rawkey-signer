/**
 * The hand-held credit-withdrawal flow (DESIGN R2, F9). It resolves the nonce, supplies and validates
 * the core fee rate (defaulting to the protocol floor rather than leaving a zero a fresh wallet would
 * report), builds the destination output script, constructs the transition through the tooling, and
 * joins the one signing path. Set `nonceContext` for offline construction, or configure a transport for
 * the nonce to be read.
 */
import { createRequire } from "node:module";
import type * as Dashcore from "@dashevo/dashcore-lib";
import type { IdentitySnapshot, Network, NonceContext, PrivateKeyInput, SignedTransition } from "../types.js";
import type { NonceSource } from "../nonce.js";
import { constructWithdrawal } from "../adapter/protocol.js";
import { signParsedTransition } from "../sign.js";
import { snapshotIdentity } from "../authorize.js";
import { snapshotPrivateKey } from "../secret.js";
import { describeType, isUint64 } from "../util.js";
import {
  InsufficientBalanceError,
  InvalidCoreFeeRateError,
  InvalidTransitionError,
  MissingStateError,
} from "../errors.js";

const nodeRequire = createRequire(import.meta.url);
const { Script, Address } = nodeRequire("@dashevo/dashcore-lib") as typeof Dashcore;

// The protocol's core fee rate must be a value in this sequence, and at least the floor of 1.
const ALLOWED_FEE_RATES = new Set<number>([1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987]);

function resolveFeeRate(rate: number | undefined): number {
  const value = rate ?? 1; // default to the protocol floor, never zero
  if (!Number.isInteger(value) || value < 1) {
    throw new InvalidCoreFeeRateError(value, "must be an integer at or above the protocol floor of 1");
  }
  if (!ALLOWED_FEE_RATES.has(value)) {
    throw new InvalidCoreFeeRateError(value, "must be a value in the protocol's allowed sequence");
  }
  return value;
}

function buildOutputScript(toAddress: string, network: Network): Uint8Array {
  const net = network === "mainnet" ? "livenet" : "testnet";
  try {
    const script = Script.buildPublicKeyHashOut(new Address(toAddress, net)) as unknown as { toBuffer(): Buffer };
    return Uint8Array.from(script.toBuffer());
  } catch {
    // An invalid destination is bad caller input, so it carries the transition error, not MissingState.
    throw new InvalidTransitionError(`the withdrawal destination address is invalid for ${network}`);
  }
}

export interface SignWithdrawalParams {
  readonly identity: IdentitySnapshot;
  readonly privateKey: PrivateKeyInput;
  readonly toAddress: string;
  /** Amount in credits. */
  readonly amount: bigint;
  readonly coreFeeRate?: number;
  readonly nonceContext?: NonceContext;
}

export async function signWithdrawal(
  ctx: { readonly nonceSource: NonceSource | undefined },
  params: SignWithdrawalParams,
): Promise<SignedTransition> {
  // Snapshot the identity first (single-read copy, then the copy is validated), so a malformed balance
  // surfaces a typed error before the preflight comparison and a changing getter cannot slip a different
  // value past validation. Everything caller-owned is captured before the nonce await, so a
  // caller-controlled nonce source cannot mutate the inputs or bypass the preflight.
  const identity = snapshotIdentity(params.identity);
  if (!isUint64(params.amount, 1n)) {
    throw new InvalidTransitionError(
      `the withdrawal amount must be an unsigned 64-bit integer at least 1 (received ${describeType(params.amount)})`,
    );
  }
  const amount = params.amount;
  if (identity.balance !== undefined && amount > identity.balance) {
    throw new InsufficientBalanceError(amount, identity.balance);
  }
  const coreFeePerByte = resolveFeeRate(params.coreFeeRate);
  const outputScript = buildOutputScript(params.toAddress, identity.network);
  const suppliedNonce = params.nonceContext?.identityNonce;
  // The raw-key copy is the last statement before the try, so a finally zeroes it on every path.
  const privateKey = snapshotPrivateKey(params.privateKey);
  try {
    let nonce = suppliedNonce;
    if (nonce === undefined) {
      if (ctx.nonceSource === undefined) {
        throw new MissingStateError("a withdrawal needs an identity nonce; supply nonceContext or configure a transport");
      }
      nonce = await ctx.nonceSource.nextIdentityNonce(identity.id);
    }
    if (!isUint64(nonce, 1n)) {
      throw new InvalidTransitionError("the identity nonce must be an unsigned 64-bit integer at least 1");
    }

    const parsed = await constructWithdrawal({ identityId: identity.id, amount, coreFeePerByte, outputScript, nonce });
    return await signParsedTransition(identity, privateKey, parsed);
  } finally {
    if ("raw" in privateKey) privateKey.raw.fill(0);
  }
}
