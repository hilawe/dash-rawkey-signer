import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import type * as Dashcore from "@dashevo/dashcore-lib";
import { SecretKey } from "../src/secret.js";
import { InvalidPrivateKeyError } from "../src/index.js";

const nodeRequire = createRequire(import.meta.url);
const { PrivateKey } = nodeRequire("@dashevo/dashcore-lib") as typeof Dashcore;

// A testnet key to decode by both WIF and raw bytes.
const ref = new PrivateKey(undefined, "testnet");
const wif = ref.toWIF();
const raw = Uint8Array.from((ref.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
const expectedPub = Uint8Array.from(ref.toPublicKey().toBuffer() as Buffer);

test("decodes a WIF to the correct compressed public key", () => {
  const sk = SecretKey.decode({ wif }, "testnet");
  assert.equal(sk.publicKey.length, 33);
  assert.deepEqual([...sk.publicKey], [...expectedPub]);
  sk.dispose();
});

test("decodes raw 32 bytes to the same compressed public key as the WIF", () => {
  const sk = SecretKey.decode({ raw }, "testnet");
  assert.deepEqual([...sk.publicKey], [...expectedPub]);
  sk.dispose();
});

test("useScalar exposes the 32-byte scalar for signing", () => {
  const sk = SecretKey.decode({ raw }, "testnet");
  const len = sk.useScalar((scalar) => scalar.length);
  assert.equal(len, 32);
  assert.deepEqual(sk.useScalar((scalar) => [...scalar]), [...raw]);
  sk.dispose();
});

test("dispose zeroes the scalar and makes it unusable", () => {
  const sk = SecretKey.decode({ raw }, "testnet");
  // capture the shared view before dispose, then confirm it is zeroed afterward
  const view = sk.useScalar((scalar) => scalar);
  assert.ok(view.some((b) => b !== 0), "scalar should be non-zero before dispose");
  sk.dispose();
  assert.ok(view.every((b) => b === 0), "scalar bytes should be zeroed after dispose");
  assert.throws(() => sk.useScalar((s) => s.length), InvalidPrivateKeyError);
});

test("dispose is idempotent", () => {
  const sk = SecretKey.decode({ raw }, "testnet");
  sk.dispose();
  sk.dispose();
});

test("an invalid WIF is rejected without leaking the input into the error", () => {
  const badWif = "this-is-not-a-valid-wif-cThisWouldBeSecret";
  try {
    SecretKey.decode({ wif: badWif }, "testnet");
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof InvalidPrivateKeyError);
    assert.equal((e as Error).message.includes(badWif), false, "error must not echo the WIF");
    assert.equal((e as { cause?: unknown }).cause, undefined, "error must not carry a cause");
  }
});

test("a raw key of the wrong length is rejected", () => {
  assert.throws(() => SecretKey.decode({ raw: new Uint8Array(31) }, "testnet"), InvalidPrivateKeyError);
  assert.throws(() => SecretKey.decode({ raw: new Uint8Array(33) }, "testnet"), InvalidPrivateKeyError);
});

test("an empty WIF is rejected", () => {
  assert.throws(() => SecretKey.decode({ wif: "" }, "testnet"), InvalidPrivateKeyError);
});

test("a public-key derivation failure surfaces the sanitized typed error, not a native throw", () => {
  // Force the derivation to throw. The decode must translate it (and, by the same catch, zero its owned
  // scalar rather than abandon it), never letting the tooling's error escape untyped.
  const proto = PrivateKey.prototype as unknown as { toPublicKey: () => unknown };
  const original = proto.toPublicKey;
  proto.toPublicKey = () => {
    throw new Error("derivation exploded");
  };
  try {
    assert.throws(() => SecretKey.decode({ raw: Uint8Array.from(raw) }, "testnet"), InvalidPrivateKeyError);
  } finally {
    proto.toPublicKey = original;
  }
});

test("a throwing cleanup cannot mask the typed error or a successful return", () => {
  // Force BOTH the derivation to throw and the intermediate buffer's zeroing to throw. The typed error
  // must survive; the best-effort cleanup must not replace it.
  const bnProto = (nodeRequire("@dashevo/dashcore-lib") as typeof Dashcore).crypto.BN
    .prototype as unknown as { toBuffer: (o?: unknown) => Buffer };
  const keyProto = PrivateKey.prototype as unknown as { toPublicKey: () => unknown };
  const originalToBuffer = bnProto.toBuffer;
  const originalToPublicKey = keyProto.toPublicKey;
  bnProto.toBuffer = function patched(this: unknown, o?: unknown) {
    const buf = originalToBuffer.call(this, o);
    (buf as unknown as { fill: () => never }).fill = () => {
      throw new Error("cleanup exploded");
    };
    return buf;
  };
  keyProto.toPublicKey = () => {
    throw new Error("derivation exploded");
  };
  try {
    assert.throws(() => SecretKey.decode({ raw: Uint8Array.from(raw) }, "testnet"), InvalidPrivateKeyError);
  } finally {
    bnProto.toBuffer = originalToBuffer;
    keyProto.toPublicKey = originalToPublicKey;
  }
  // And with only the cleanup hostile (derivation healthy), decode still succeeds.
  bnProto.toBuffer = function patched(this: unknown, o?: unknown) {
    const buf = originalToBuffer.call(this, o);
    (buf as unknown as { fill: () => never }).fill = () => {
      throw new Error("cleanup exploded");
    };
    return buf;
  };
  try {
    const sk = SecretKey.decode({ raw: Uint8Array.from(raw) }, "testnet");
    assert.deepEqual([...sk.publicKey], [...expectedPub], "a hostile cleanup does not replace the return");
  } finally {
    bnProto.toBuffer = originalToBuffer;
  }
});
