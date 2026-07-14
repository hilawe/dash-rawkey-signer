import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RawKeySignerError,
  KeyDisabledError,
  KeyPurposeMismatchError,
  KeySecurityLevelMismatchError,
  AuthorIdentityMismatchError,
  UnsupportedTransitionTypeError,
  BroadcastError,
  NonceConflictError,
  InsufficientBalanceError,
  InvalidCoreFeeRateError,
} from "../src/index.js";

test("errors extend the base and Error, and carry a stable code and name", () => {
  const e = new KeyDisabledError(3);
  assert.ok(e instanceof RawKeySignerError);
  assert.ok(e instanceof Error);
  assert.equal(e.code, "KEY_DISABLED");
  assert.equal(e.keyId, 3);
  assert.equal(e.name, "KeyDisabledError");
});

test("KeyPurposeMismatchError carries structured, secret-free fields", () => {
  const e = new KeyPurposeMismatchError(1, 3, [0], 5);
  assert.equal(e.code, "KEY_PURPOSE_MISMATCH");
  assert.equal(e.keyId, 1);
  assert.equal(e.actualPurpose, 3);
  assert.deepEqual(e.requiredPurpose, [0]);
  assert.equal(e.transitionType, 5);
});

test("KeySecurityLevelMismatchError carries structured fields", () => {
  const e = new KeySecurityLevelMismatchError(2, 3, [0, 1], 5);
  assert.equal(e.code, "KEY_SECURITY_LEVEL_MISMATCH");
  assert.equal(e.actualSecurityLevel, 3);
  assert.deepEqual(e.requiredSecurityLevel, [0, 1]);
});

test("AuthorIdentityMismatchError names both ids in fields and message", () => {
  const e = new AuthorIdentityMismatchError("AAA", "BBB");
  assert.equal(e.code, "AUTHOR_IDENTITY_MISMATCH");
  assert.equal(e.expectedIdentityId, "AAA");
  assert.equal(e.transitionAuthorId, "BBB");
  assert.match(e.message, /AAA/);
  assert.match(e.message, /BBB/);
});

test("UnsupportedTransitionTypeError keeps the type when known", () => {
  const e = new UnsupportedTransitionTypeError("no requirement", 99);
  assert.equal(e.code, "UNSUPPORTED_TRANSITION_TYPE");
  assert.equal(e.transitionType, 99);
});

test("BroadcastError defaults retryable false and keeps details", () => {
  const e1 = new BroadcastError("rejected");
  assert.equal(e1.retryable, false);
  assert.equal(e1.platformCode, undefined);
  const e2 = new BroadcastError("timeout", { retryable: true, platformCode: 42, transitionHash: "deadbeef" });
  assert.equal(e2.retryable, true);
  assert.equal(e2.platformCode, 42);
  assert.equal(e2.transitionHash, "deadbeef");
});

test("NonceConflictError carries the observed nonce for retry", () => {
  const e = new NonceConflictError("conflict", 7n);
  assert.equal(e.code, "NONCE_CONFLICT");
  assert.equal(e.observedNonce, 7n);
});

test("balance and fee errors carry their numeric context", () => {
  const b = new InsufficientBalanceError(12000000000n, 800000000n);
  assert.equal(b.required, 12000000000n);
  assert.equal(b.available, 800000000n);
  const f = new InvalidCoreFeeRateError(0, "zero not allowed");
  assert.equal(f.rate, 0);
});

test("every error can be branched by code and by instanceof", () => {
  const errs: RawKeySignerError[] = [new KeyDisabledError(1), new NonceConflictError("x")];
  assert.equal(errs.filter((e) => e.code === "KEY_DISABLED").length, 1);
  assert.equal(errs.filter((e) => e instanceof NonceConflictError).length, 1);
});
