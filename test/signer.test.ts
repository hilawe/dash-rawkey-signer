import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import type * as Dashcore from "@dashevo/dashcore-lib";
import { createDefaultNonceSource, createRawKeySigner } from "../src/index.js";
import { ensureLoaded } from "../src/adapter/protocol.js";
import type { IdentitySnapshot, SubmissionResult } from "../src/index.js";
import {
  ClientRequiredError,
  InvalidIdentitySnapshotError,
  InvalidPrivateKeyError,
  InvalidTransitionError,
  isRawKeySignerError,
  MissingStateError,
  RawKeySignerError,
  UnexpectedError,
} from "../src/index.js";
import type { Transport } from "../src/index.js";

const req = createRequire(import.meta.url);
const wasm = req("@dashevo/wasm-dpp") as any;
const { PrivateKey } = req("@dashevo/dashcore-lib") as typeof Dashcore;

const rawOf = (p: InstanceType<typeof PrivateKey>) =>
  Uint8Array.from((p.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
const pubOf = (p: InstanceType<typeof PrivateKey>) => Uint8Array.from(p.toPublicKey().toBuffer() as Buffer);

async function fixture(): Promise<{ identity: IdentitySnapshot; raw: Uint8Array; unsigned: Uint8Array }> {
  await ensureLoaded();
  const master = new PrivateKey(undefined, "testnet");
  const idBytes = new Uint8Array(32).fill(3);
  const identity: IdentitySnapshot = {
    network: "testnet",
    protocolVersion: 1,
    id: idBytes,
    publicKeys: [{ id: 0, purpose: 0, securityLevel: 0, keyType: 0, disabled: false, data: pubOf(master) }],
  };
  const ust = new wasm.IdentityUpdateTransition(1);
  ust.setIdentityId(wasm.Identifier.from(Buffer.from(idBytes)));
  if (typeof ust.setRevision === "function") ust.setRevision(2n);
  ust.setPublicKeyIdsToDisable(Uint32Array.from([1]));
  return { identity, raw: rawOf(master), unsigned: Uint8Array.from(ust.toBuffer()) };
}

test("signer.signTransition signs the general path", async () => {
  const { identity, raw, unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signTransition({ identity, privateKey: { raw }, transition: unsigned });
  assert.equal(signed.signingKeyId, 0);
  assert.ok(signed.bytes.length > unsigned.length, "signed transition should carry a signature");
});

test("signer.authorize resolves the key without signing", async () => {
  const { identity, raw, unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  const info = await signer.authorize({ identity, privateKey: { raw }, transition: unsigned });
  assert.deepEqual(info, { keyId: 0, purpose: 0, securityLevel: 0 });
});

test("broadcast without a transport is a ClientRequiredError", async () => {
  const { unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(() => signer.broadcast(unsigned), ClientRequiredError);
});

test("broadcast rejects a non-transition byte array before touching the transport", async () => {
  let broadcastCalled = false;
  const transport: Transport = {
    async broadcast() {
      broadcastCalled = true;
      return { transitionHash: new Uint8Array(0), accepted: true };
    },
    async getIdentityNonce() {
      return 0n;
    },
    async getIdentityContractNonce() {
      return 0n;
    },
  };
  const signer = createRawKeySigner({ network: "testnet", transport });
  await assert.rejects(() => signer.broadcast(new Uint8Array([1, 2, 3, 4, 5])), InvalidTransitionError);
  assert.equal(broadcastCalled, false, "transport must not be called for invalid input");
});

test("broadcast passes a valid signed transition to the transport", async () => {
  const { identity, raw, unsigned } = await fixture();
  let received: Uint8Array | null = null;
  const result: SubmissionResult = { transitionHash: new Uint8Array([9, 9]), accepted: true };
  const transport: Transport = {
    async broadcast(bytes) {
      received = bytes;
      return result;
    },
    async getIdentityNonce() {
      return 0n;
    },
    async getIdentityContractNonce() {
      return 0n;
    },
  };
  const signer = createRawKeySigner({ network: "testnet", transport });
  const signed = await signer.signTransition({ identity, privateKey: { raw }, transition: unsigned });
  const out = await signer.broadcast(signed);
  assert.equal(out, result);
  assert.deepEqual(received, signed.bytes);
});

test("withKey binds one key, signs repeatedly, and zeroes on dispose", async () => {
  const { identity, raw, unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  const bound = signer.withKey({ raw });
  const a = await bound.signTransition({ identity, transition: unsigned });
  assert.equal(a.signingKeyId, 0);
  bound.dispose();
  assert.ok(raw.every((b) => b === 0), "the bound raw key bytes should be zeroed after dispose");
  await assert.rejects(() => bound.signTransition({ identity, transition: unsigned }), ClientRequiredError);
});

test("withKey rejects a malformed key at bind time with a typed error, not a native TypeError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  assert.throws(() => signer.withKey({ raw: undefined } as unknown as { raw: Uint8Array }), InvalidPrivateKeyError);
});

test("a non-Uint8Array transition is refused with a typed error on both the sign and authorize paths", async () => {
  const { identity, raw } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  const bad = { identity, privateKey: { raw }, transition: undefined as unknown as Uint8Array };
  await assert.rejects(() => signer.signTransition(bad), InvalidTransitionError);
  await assert.rejects(() => signer.authorize(bad), InvalidTransitionError);
});

// The one remaining channel for caller code to throw arbitrary values into the boundary net. Every input
// path now defuses hostile byte objects with memcpy copies and typed guards, so the net's catch-all is
// exercised through an injected transport, which is real caller code the library invokes.
function throwingTransport(value: unknown): Transport {
  return {
    async broadcast(): Promise<SubmissionResult> {
      throw value;
    },
    async getIdentityNonce() {
      return 1n;
    },
    async getIdentityContractNonce() {
      return 1n;
    },
  };
}

test("the boundary net turns an exotic native throw into a typed error, not a raw TypeError", async () => {
  const { unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet", transport: throwingTransport(new TypeError("raw native")) });
  const err = await signer.broadcast(unsigned).then(
    () => null,
    (e) => e,
  );
  assert.ok(err instanceof RawKeySignerError, "an exotic throw must surface as a typed error");
  assert.ok(err instanceof UnexpectedError, "an unanticipated throw becomes UnexpectedError");
});

test("the net stays total even when the thrown value is a proxy that throws while being classified", async () => {
  const { unsigned } = await fixture();
  // A proxy whose getPrototypeOf trap throws breaks the instanceof the net uses to classify the throw.
  const hostile = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("classification trap");
      },
    },
  );
  const signer = createRawKeySigner({ network: "testnet", transport: throwingTransport(hostile) });
  const err = await signer.broadcast(unsigned).then(
    () => null,
    (e) => e,
  );
  assert.ok(err instanceof UnexpectedError, "a throw that resists classification still becomes a typed error");
});

test("UnexpectedError does not retain the thrown value, so a key-bearing throw cannot leak the key", async () => {
  const { raw, unsigned } = await fixture();
  // Caller-controlled code throws an object that references the caller's own key buffer. The library must
  // not keep that object on the error, since an error is often logged (R5).
  const signer = createRawKeySigner({
    network: "testnet",
    transport: throwingTransport({ note: "boom", secret: raw }),
  });
  const err = (await signer.broadcast(unsigned).then(
    () => null,
    (e) => e,
  )) as UnexpectedError;
  assert.ok(err instanceof UnexpectedError);
  assert.equal((err as unknown as { cause?: unknown }).cause, undefined, "no thrown object is retained as cause");
  assert.equal(err.thrownType, "object", "only the safe typeof is recorded");
  const seen = JSON.stringify(err, Object.getOwnPropertyNames(err));
  assert.ok(!seen.includes("secret"), "nothing reachable on the error references the thrown key holder");
});

test("a proxy that forges our error prototype does not pass classification (non-spoofable brand)", () => {
  const forged = new Proxy({ secret: "leak" }, { getPrototypeOf: () => RawKeySignerError.prototype });
  assert.ok(forged instanceof RawKeySignerError, "the proxy spoofs instanceof");
  assert.equal(isRawKeySignerError(forged), false, "the brand rejects the forgery");
});

test("a forged secret-bearing error thrown by caller code is not rethrown as itself", async () => {
  const { raw, unsigned } = await fixture();
  // The thrown value forges our prototype (so instanceof would trust it) and carries the key. The net must
  // classify by brand, reject it, and surface an UnexpectedError that references neither the object nor the key.
  const forged = new Proxy({ secret: raw }, { getPrototypeOf: () => RawKeySignerError.prototype });
  const signer = createRawKeySigner({ network: "testnet", transport: throwingTransport(forged) });
  const err = (await signer.broadcast(unsigned).then(
    () => null,
    (e) => e,
  )) as UnexpectedError;
  assert.ok(err instanceof UnexpectedError, "a forged error becomes UnexpectedError, not passed through");
  assert.notStrictEqual(err as unknown, forged, "the caller's object is not the surfaced error");
});

test("createRawKeySigner validates its options with a typed error", () => {
  assert.throws(() => createRawKeySigner(null as unknown as { network: "testnet" }), MissingStateError);
  assert.throws(
    () => createRawKeySigner({ network: "regtest" as unknown as "testnet" }),
    MissingStateError,
  );
});

test("createRawKeySigner accepts every supported network, including local for a devnet", () => {
  for (const network of ["mainnet", "testnet", "local"] as const) {
    assert.doesNotThrow(() => createRawKeySigner({ network }), `network ${network} must be accepted`);
  }
});

test("the default nonce source, called directly, surfaces typed errors at its own boundary", async () => {
  const ok = { transitionHash: new Uint8Array(0), accepted: true };
  const nonBigint: Transport = {
    broadcast: async () => ok,
    getIdentityNonce: async () => 5 as unknown as bigint,
    getIdentityContractNonce: async () => 0n,
  };
  const source = createDefaultNonceSource(nonBigint);
  await assert.rejects(() => source.nextIdentityNonce(new Uint8Array(32)), InvalidTransitionError);

  const okTransport: Transport = {
    broadcast: async () => ok,
    getIdentityNonce: async () => 1n,
    getIdentityContractNonce: async () => 1n,
  };
  const guarded = createDefaultNonceSource(okTransport);
  // An identifier whose byte access throws would make toHex throw a native error without the boundary.
  const hostileId = new Proxy(new Uint8Array(32), {
    get(target, prop) {
      if (prop === "length") return 32;
      throw new Error("hostile index");
    },
  });
  await assert.rejects(() => guarded.nextIdentityNonce(hostileId as Uint8Array), RawKeySignerError);
});

test("the general path snapshots the identity and key, so mutation during the await changes nothing", async () => {
  const { identity, raw, unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  const keyCopy = Uint8Array.from(raw);
  const started = signer.signTransition({ identity, privateKey: { raw: keyCopy }, transition: unsigned });
  // The snapshots are taken in the call's synchronous prefix, so mutating the caller's objects now, while
  // the parse await is pending, must not change what is authorized and signed.
  (identity as { publicKeys: unknown }).publicKeys = [];
  keyCopy.fill(0);
  const signed = await started;
  assert.equal(signed.signingKeyId, 0, "signed with the pre-mutation identity and key");
});

test("authorize snapshots the identity and key, so mutation during the await changes nothing", async () => {
  const { identity, raw, unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "testnet" });
  const keyCopy = Uint8Array.from(raw);
  const started = signer.authorize({ identity, privateKey: { raw: keyCopy }, transition: unsigned });
  (identity as { publicKeys: unknown }).publicKeys = [];
  keyCopy.fill(0);
  const info = await started;
  assert.equal(info.keyId, 0, "authorized against the pre-mutation identity and key");
});

test("broadcast snapshots its bytes, so mutation during the parse await cannot change what is sent", async () => {
  const { identity, raw, unsigned } = await fixture();
  let received: Uint8Array | undefined;
  const transport: Transport = {
    async broadcast(bytes) {
      received = bytes;
      return { transitionHash: new Uint8Array(32), accepted: true };
    },
    async getIdentityNonce() {
      return 1n;
    },
    async getIdentityContractNonce() {
      return 1n;
    },
  };
  const signer = createRawKeySigner({ network: "testnet", transport });
  const signed = await signer.signTransition({ identity, privateKey: { raw }, transition: unsigned });
  const original = Uint8Array.from(signed.bytes);
  const started = signer.broadcast(signed.bytes);
  // Corrupt the caller's array while the parse await is pending; the transport must get the snapshot.
  signed.bytes.fill(0);
  await started;
  assert.deepEqual(received, original, "the transport received the pre-mutation bytes");
});

test("broadcast refuses a missing or shapeless input with a precise typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(() => signer.broadcast(null as unknown as Uint8Array), InvalidTransitionError);
  await assert.rejects(() => signer.broadcast(undefined as unknown as Uint8Array), InvalidTransitionError);
  await assert.rejects(
    () => signer.broadcast({ bytes: "nope" } as unknown as Uint8Array),
    InvalidTransitionError,
  );
});

test("bound dispose never throws, even when the key's fill is hostile", () => {
  const signer = createRawKeySigner({ network: "testnet" });
  class HostileFill extends Uint8Array {
    fill(): this {
      throw new Error("no fill");
    }
  }
  const bound = signer.withKey({ raw: new HostileFill(32) });
  assert.doesNotThrow(() => bound.dispose());
});

test("initialize preloads the tooling and is idempotent", async () => {
  const { initialize } = await import("../src/index.js");
  await initialize();
  await initialize();
});

test("the signer's network is enforced: a mismatched identity snapshot is refused", async () => {
  const { identity, raw, unsigned } = await fixture();
  const signer = createRawKeySigner({ network: "local" });
  const mainnetIdentity = { ...identity, network: "mainnet" as const };
  await assert.rejects(
    () => signer.signTransition({ identity: mainnetIdentity, privateKey: { raw }, transition: unsigned }),
    InvalidIdentitySnapshotError,
  );
  await assert.rejects(
    () => signer.authorize({ identity: mainnetIdentity, privateKey: { raw }, transition: unsigned }),
    InvalidIdentitySnapshotError,
  );
  await assert.rejects(
    () =>
      signer.signWithdrawal({
        identity: { ...mainnetIdentity, balance: 100000000n },
        privateKey: { raw },
        toAddress: "XdgeikBoJPTgTsvAKYhTGJri3AL1JJ3iRT",
        amount: 1000n,
        nonceContext: { identityNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
});

test("concurrent allocations from the default nonce source are distinct and ascending", async () => {
  // Five concurrent allocations against a transport that always reports the same current nonce. The
  // in-process serialization must hand out five distinct, sequentially ascending values, never a collision.
  const transport: Transport = {
    async broadcast() {
      return { transitionHash: new Uint8Array(32), accepted: true };
    },
    async getIdentityNonce() {
      return 7n;
    },
    async getIdentityContractNonce() {
      return 7n;
    },
  };
  const source = createDefaultNonceSource(transport);
  const id = new Uint8Array(32).fill(4);
  const nonces = await Promise.all(Array.from({ length: 5 }, () => source.nextIdentityNonce(id)));
  assert.deepEqual([...nonces].sort((a, b) => (a < b ? -1 : 1)), [8n, 9n, 10n, 11n, 12n]);
  assert.equal(new Set(nonces.map(String)).size, 5, "no two concurrent signs may share a nonce");
});
