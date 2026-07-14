import { test } from "node:test";
import assert from "node:assert/strict";
import { authorizeKey, snapshotIdentity, validateIdentitySnapshot, type TransitionDescriptor } from "../src/authorize.js";
import type { IdentitySnapshot, RegisteredKey } from "../src/index.js";
import {
  AuthorIdentityMismatchError,
  KeyNotOnIdentityError,
  KeyPurposeMismatchError,
  KeySecurityLevelMismatchError,
  KeyDisabledError,
  DeclaredSigningKeyMismatchError,
  InvalidIdentitySnapshotError,
} from "../src/index.js";

const ID = new Uint8Array(32).fill(7);
const pub = (b: number) => new Uint8Array(33).fill(b);

function mkKey(id: number, purpose: number, securityLevel: number, dataByte: number, disabled = false): RegisteredKey {
  return { id, purpose, securityLevel, keyType: 0, disabled, data: pub(dataByte) };
}

function identity(keys: RegisteredKey[]): IdentitySnapshot {
  return { network: "testnet", protocolVersion: 1, id: ID, publicKeys: keys };
}

// A document-style descriptor: authentication purpose, security HIGH or stronger.
const docDescriptor: TransitionDescriptor = {
  transitionType: 1,
  authorId: ID,
  requiredPurposes: [0],
  allowedSecurityLevels: [0, 1, 2],
};

test("happy path returns the matching enabled key with the right purpose and security", () => {
  const auth = mkKey(1, 0, 2, 0xaa);
  const key = authorizeKey(identity([mkKey(0, 0, 0, 0xbb), auth]), pub(0xaa), docDescriptor);
  assert.equal(key.id, 1);
});

test("author mismatch is rejected before anything else", () => {
  const other = new Uint8Array(32).fill(9);
  assert.throws(
    () => authorizeKey(identity([mkKey(1, 0, 2, 0xaa)]), pub(0xaa), { ...docDescriptor, authorId: other }),
    AuthorIdentityMismatchError,
  );
});

test("a key not registered on the identity is rejected", () => {
  assert.throws(() => authorizeKey(identity([mkKey(1, 0, 2, 0xaa)]), pub(0x11), docDescriptor), KeyNotOnIdentityError);
});

test("wrong purpose reports KeyPurposeMismatchError", () => {
  const transferKey = mkKey(3, 3, 1, 0xcc); // transfer purpose, not authentication
  try {
    authorizeKey(identity([transferKey]), pub(0xcc), docDescriptor);
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof KeyPurposeMismatchError);
    assert.equal(e.keyId, 3);
    assert.equal(e.actualPurpose, 3);
  }
});

test("right purpose but disallowed security reports KeySecurityLevelMismatchError", () => {
  const mediumKey = mkKey(4, 0, 3, 0xdd); // auth purpose, MEDIUM (3) not in allowed [0,1,2]
  try {
    authorizeKey(identity([mediumKey]), pub(0xdd), docDescriptor);
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof KeySecurityLevelMismatchError);
    assert.equal(e.actualSecurityLevel, 3);
  }
});

test("right purpose and security but disabled reports KeyDisabledError", () => {
  const disabled = mkKey(5, 0, 2, 0xee, true);
  assert.throws(() => authorizeKey(identity([disabled]), pub(0xee), docDescriptor), KeyDisabledError);
});

test("narrowest failure: a disabled eligible key beats a wrong-purpose match for the same bytes", () => {
  // two registrations share bytes: one wrong purpose, one right purpose but disabled -> report disabled
  const wrongPurpose = mkKey(6, 3, 2, 0xf0);
  const rightButDisabled = mkKey(7, 0, 2, 0xf0, true);
  assert.throws(() => authorizeKey(identity([wrongPurpose, rightButDisabled]), pub(0xf0), docDescriptor), KeyDisabledError);
});

test("multiple fully-eligible duplicates resolve deterministically to the lowest key id", () => {
  const dupHigh = mkKey(9, 0, 2, 0x55);
  const dupLow = mkKey(2, 0, 2, 0x55);
  const key = authorizeKey(identity([dupHigh, dupLow]), pub(0x55), docDescriptor);
  assert.equal(key.id, 2);
});

test("a declared signing-key id is honored when it is eligible", () => {
  const k2 = mkKey(2, 0, 2, 0x66);
  const k5 = mkKey(5, 0, 2, 0x66);
  const key = authorizeKey(identity([k2, k5]), pub(0x66), { ...docDescriptor, declaredSigningKeyId: 5 });
  assert.equal(key.id, 5);
});

test("a declared signing-key id absent from the identity is a declaration mismatch, not ambiguity", () => {
  const k2 = mkKey(2, 0, 2, 0x77);
  assert.throws(
    () => authorizeKey(identity([k2]), pub(0x77), { ...docDescriptor, declaredSigningKeyId: 99 }),
    DeclaredSigningKeyMismatchError,
  );
});

test("a declared key that is present but ineligible reports ITS own defect", () => {
  // declared key (id 1) has the wrong purpose; a sibling with the same bytes is right-purpose-but-disabled.
  const declaredWrongPurpose = mkKey(1, 3, 2, 0x78); // transfer, not authentication
  const siblingDisabled = mkKey(2, 0, 2, 0x78, true);
  try {
    authorizeKey(identity([declaredWrongPurpose, siblingDisabled]), pub(0x78), {
      ...docDescriptor,
      declaredSigningKeyId: 1,
    });
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof KeyPurposeMismatchError, `expected purpose error, got ${(e as Error).constructor.name}`);
    assert.equal((e as KeyPurposeMismatchError).keyId, 1);
  }
});

test("a declared key that is present but disabled reports KeyDisabledError for that key", () => {
  const declaredDisabled = mkKey(4, 0, 2, 0x79, true);
  try {
    authorizeKey(identity([declaredDisabled]), pub(0x79), { ...docDescriptor, declaredSigningKeyId: 4 });
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof KeyDisabledError);
    assert.equal((e as KeyDisabledError).keyId, 4);
  }
});

test("security membership is a SET, not an ordering: master signs a high-required transition", () => {
  const master = mkKey(0, 0, 0, 0x88); // MASTER (0) is in allowed [0,1,2]
  const key = authorizeKey(identity([master]), pub(0x88), docDescriptor);
  assert.equal(key.id, 0);
});

test("noncontiguous allowed set rejects an in-between level a `<=` implementation would accept", () => {
  const desc: TransitionDescriptor = { ...docDescriptor, allowedSecurityLevels: [0, 2] };
  const level1 = mkKey(1, 0, 1, 0x90); // CRITICAL (1) is NOT in {0,2}
  assert.throws(() => authorizeKey(identity([level1]), pub(0x90), desc), KeySecurityLevelMismatchError);
});

test("an allowed set of only [2] rejects a numerically stronger level 0 key", () => {
  const desc: TransitionDescriptor = { ...docDescriptor, allowedSecurityLevels: [2] };
  const master = mkKey(0, 0, 0, 0x91); // MASTER (0) not in {2}
  assert.throws(() => authorizeKey(identity([master]), pub(0x91), desc), KeySecurityLevelMismatchError);
});

test("empty requiredPurposes fails closed (no purpose can be authorized)", () => {
  const desc: TransitionDescriptor = { ...docDescriptor, requiredPurposes: [] };
  const k = mkKey(1, 0, 2, 0x92);
  assert.throws(() => authorizeKey(identity([k]), pub(0x92), desc), KeyPurposeMismatchError);
});

test("empty allowedSecurityLevels fails closed", () => {
  const desc: TransitionDescriptor = { ...docDescriptor, allowedSecurityLevels: [] };
  const k = mkKey(1, 0, 2, 0x93);
  assert.throws(() => authorizeKey(identity([k]), pub(0x93), desc), KeySecurityLevelMismatchError);
});

test("all-disabled eligible duplicates report KeyDisabledError, never resolve", () => {
  const d1 = mkKey(2, 0, 2, 0x94, true);
  const d2 = mkKey(5, 0, 2, 0x94, true);
  assert.throws(() => authorizeKey(identity([d1, d2]), pub(0x94), docDescriptor), KeyDisabledError);
});

test("a malformed snapshot with a non-integer key id is rejected before authorization", () => {
  const bad = { id: Number.NaN, purpose: 0, securityLevel: 2, keyType: 0, disabled: false, data: pub(0x95) };
  assert.throws(() => authorizeKey(identity([bad]), pub(0x95), docDescriptor), InvalidIdentitySnapshotError);
});

test("a snapshot with duplicate key ids is rejected", () => {
  const a = mkKey(3, 0, 2, 0xa1);
  const b = mkKey(3, 0, 2, 0xa2);
  assert.throws(() => validateIdentitySnapshot(identity([a, b])), InvalidIdentitySnapshotError);
});

test("validateIdentitySnapshot accepts a well-formed snapshot", () => {
  validateIdentitySnapshot(identity([mkKey(0, 0, 0, 0xb1), mkKey(1, 0, 2, 0xb2)]));
});

test("an unknown or missing network is rejected, never silently mapped to testnet encoding", () => {
  const keys = [mkKey(0, 0, 2, 0xc1)];
  const noNetwork = { ...identity(keys), network: undefined as unknown as "testnet" };
  assert.throws(() => validateIdentitySnapshot(noNetwork), InvalidIdentitySnapshotError);
  const wrongNetwork = { ...identity(keys), network: "regtest" as unknown as "testnet" };
  assert.throws(() => validateIdentitySnapshot(wrongNetwork), InvalidIdentitySnapshotError);
  // The supported devnet value stays accepted.
  validateIdentitySnapshot({ ...identity(keys), network: "local" });
});

test("an out-of-range revision is rejected by the shared validator, not left to wrap in the tooling", () => {
  const keys = [mkKey(0, 0, 0, 0xc2)];
  assert.throws(
    () => validateIdentitySnapshot({ ...identity(keys), revision: -1n }),
    InvalidIdentitySnapshotError,
  );
  assert.throws(
    () => validateIdentitySnapshot({ ...identity(keys), revision: 2n ** 64n }),
    InvalidIdentitySnapshotError,
  );
  validateIdentitySnapshot({ ...identity(keys), revision: 0n });
});

test("the exported helpers are safe on hostile input, outside the signer's guard", () => {
  const keys = [mkKey(0, 0, 2, 0xd1)];
  // A throwing getter surfaces the typed snapshot error, not a native throw.
  const throwingGetter = Object.defineProperty({ ...identity(keys) }, "network", {
    get() {
      throw new Error("hostile getter");
    },
  });
  assert.throws(() => validateIdentitySnapshot(throwingGetter), InvalidIdentitySnapshotError);
  assert.throws(() => snapshotIdentity(throwingGetter), InvalidIdentitySnapshotError);
  // A byte view whose iterator throws cannot escape natively from the copy.
  class HostileBytes extends Uint8Array {
    [Symbol.iterator](): IterableIterator<number> {
      throw new Error("hostile iterator");
    }
  }
  const hostileId = { ...identity(keys), id: new HostileBytes(32) };
  assert.throws(() => snapshotIdentity(hostileId), InvalidIdentitySnapshotError);
});

test("snapshotIdentity reads each field once, so a changing getter cannot defeat validation", () => {
  const keys = [mkKey(0, 0, 2, 0xd2)];
  let reads = 0;
  const flipping = Object.defineProperty({ ...identity(keys) }, "network", {
    get() {
      reads += 1;
      return reads === 1 ? "testnet" : "regtest";
    },
  });
  // The single read happens during the copy, and the copy is what gets validated, so whichever value the
  // one read returned is the value both validated and used. A first-read of testnet stays testnet.
  const snap = snapshotIdentity(flipping);
  assert.equal(snap.network, "testnet");
  assert.equal(reads, 1, "the network getter was read exactly once");
});

test("snapshotIdentity picks up inherited fields and drops unknown extras", () => {
  const keys = [mkKey(0, 0, 2, 0xd3)];
  const proto = identity(keys);
  const child = Object.create(proto) as typeof proto & { junk?: string };
  child.junk = "not part of the snapshot";
  const snap = snapshotIdentity(child);
  assert.equal(snap.network, "testnet", "inherited fields are read through the prototype chain");
  assert.equal(snap.protocolVersion, 1);
  assert.ok(!("junk" in snap), "unknown extra properties are dropped");
});

test("snapshotIdentity never aliases the caller's array, even when its map is overridden", () => {
  const callerKey = mkKey(0, 0, 2, 0xd4);
  const hostileArray = [callerKey];
  // A hostile array whose map returns the source array itself, hoping the copy aliases caller data.
  (hostileArray as unknown as { map: unknown }).map = () => hostileArray;
  const snap = snapshotIdentity({ ...identity([]), publicKeys: hostileArray });
  assert.notEqual(snap.publicKeys, hostileArray, "the snapshot owns a fresh array");
  assert.notEqual(snap.publicKeys[0], callerKey, "the snapshot owns fresh key objects");
  assert.notEqual(snap.publicKeys[0]?.data, callerKey.data, "the snapshot owns fresh key bytes");
  // Mutating the caller's objects after the snapshot changes nothing in it.
  (callerKey as { id: number }).id = 999;
  callerKey.data.fill(0xff);
  assert.equal(snap.publicKeys[0]?.id, 0);
  assert.notEqual(snap.publicKeys[0]?.data[0], 0xff);
});
