import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import type * as Dashcore from "@dashevo/dashcore-lib";
import { createRawKeySigner } from "../src/index.js";
import { ensureLoaded } from "../src/adapter/protocol.js";
import type { IdentitySnapshot } from "../src/index.js";
import {
  InsufficientBalanceError,
  InvalidCoreFeeRateError,
  InvalidPrivateKeyError,
  InvalidTransitionError,
  MissingStateError,
} from "../src/index.js";

const req = createRequire(import.meta.url);
const { PrivateKey } = req("@dashevo/dashcore-lib") as typeof Dashcore;

const rawOf = (p: InstanceType<typeof PrivateKey>) =>
  Uint8Array.from((p.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
const pubOf = (p: InstanceType<typeof PrivateKey>) => Uint8Array.from(p.toPublicKey().toBuffer() as Buffer);

const transfer = new PrivateKey(undefined, "testnet");
const toAddress = new PrivateKey(undefined, "testnet").toAddress("testnet").toString();

function identity(balance?: bigint): IdentitySnapshot {
  return {
    network: "testnet",
    protocolVersion: 1,
    id: new Uint8Array(32).fill(5),
    ...(balance !== undefined ? { balance } : {}),
    // key id 2, TRANSFER purpose (3), CRITICAL security (1)
    publicKeys: [{ id: 2, purpose: 3, securityLevel: 1, keyType: 0, disabled: false, data: pubOf(transfer) }],
  };
}

const base = {
  privateKey: { raw: rawOf(transfer) },
  toAddress,
  amount: 1_000_000n,
  nonceContext: { identityNonce: 1n },
} as const;

test("signWithdrawal constructs and signs with the transfer key, defaulting the fee to the floor", async () => {
  await ensureLoaded();
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signWithdrawal({ identity: identity(100_000_000n), ...base });
  assert.equal(signed.transitionType, 6, "IdentityCreditWithdrawal");
  assert.equal(signed.signingKeyId, 2);
  assert.ok(signed.signature.length > 0);
});

test("an out-of-sequence fee rate is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () => signer.signWithdrawal({ identity: identity(100_000_000n), ...base, coreFeeRate: 4 }),
    InvalidCoreFeeRateError,
  );
});

test("a withdrawal above the known balance is rejected by the preflight", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () => signer.signWithdrawal({ identity: identity(500_000n), ...base }),
    InsufficientBalanceError,
  );
});

test("an invalid amount and an invalid address carry the transition error, not a misleading class", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const { amount: _a, ...noAmount } = base;
  await assert.rejects(
    () => signer.signWithdrawal({ identity: identity(100_000_000n), ...noAmount, amount: 0n }),
    InvalidTransitionError,
  );
  const { toAddress: _t, ...noAddress } = base;
  await assert.rejects(
    () => signer.signWithdrawal({ identity: identity(100_000_000n), ...noAddress, toAddress: "not-an-address" }),
    InvalidTransitionError,
  );
});

test("an in-range but unsupported protocol version is refused with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () => signer.signWithdrawal({ identity: { ...identity(100_000_000n), protocolVersion: 4294967295 }, ...base }),
    InvalidTransitionError,
  );
});

test("a malformed private key is refused with a typed error, not a native TypeError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const { privateKey: _omit, ...rest } = base;
  await assert.rejects(
    () =>
      signer.signWithdrawal({
        identity: identity(100_000_000n),
        privateKey: { raw: undefined } as unknown as { raw: Uint8Array },
        ...rest,
      }),
    InvalidPrivateKeyError,
  );
});

test("the inputs are snapshotted, so a nonce source that mutates the caller's identity is ignored", async () => {
  const mutable = identity(100_000_000n);
  const signer = createRawKeySigner({
    network: "testnet",
    transport: {
      async broadcast() {
        return { transitionHash: new Uint8Array(0), accepted: true };
      },
      async getIdentityNonce() {
        // Corrupt the caller's identity during the await; the snapshot must have captured the original.
        (mutable as { id: unknown }).id = undefined;
        return 5n;
      },
      async getIdentityContractNonce() {
        return 0n;
      },
    },
  });
  const { nonceContext: _omit, ...noNonce } = base;
  const signed = await signer.signWithdrawal({ identity: mutable, ...noNonce });
  assert.equal(signed.transitionType, 6, "signing used the snapshot, not the mutated identity");
});

test("no nonce and no transport is a MissingStateError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const { nonceContext: _omit, ...noNonce } = base;
  await assert.rejects(
    () => signer.signWithdrawal({ identity: identity(100_000_000n), ...noNonce }),
    MissingStateError,
  );
});

test("the nonce is drawn from a configured transport when no nonceContext is given", async () => {
  let asked = false;
  const signer = createRawKeySigner({
    network: "testnet",
    transport: {
      async broadcast() {
        return { transitionHash: new Uint8Array(0), accepted: true };
      },
      async getIdentityNonce() {
        asked = true;
        return 41n;
      },
      async getIdentityContractNonce() {
        return 0n;
      },
    },
  });
  const { nonceContext: _omit, ...noNonce } = base;
  const signed = await signer.signWithdrawal({ identity: identity(100_000_000n), ...noNonce });
  assert.equal(asked, true, "the transport nonce read should be used");
  assert.equal(signed.transitionType, 6);
});
