import { test } from "node:test";
import assert from "node:assert/strict";
import { snapshotFromDashIdentity } from "../src/index.js";
import type { DashIdentityLike } from "../src/index.js";
import { InvalidIdentitySnapshotError } from "../src/index.js";

function mockIdentity(over: Partial<{ balance: bigint | number; revision: bigint | number }> = {}): DashIdentityLike {
  const idBytes = new Uint8Array(32).fill(9);
  const keyData = new Uint8Array(33).fill(2);
  return {
    getId: () => ({ toBuffer: () => idBytes }),
    getPublicKeys: () => [
      { getId: () => 0, getPurpose: () => 0, getSecurityLevel: () => 0, getType: () => 0, getData: () => keyData, getDisabledAt: () => undefined },
      { getId: () => 1, getPurpose: () => 0, getSecurityLevel: () => 2, getType: () => 0, getData: () => keyData, getDisabledAt: () => new Date() },
    ],
    getBalance: () => over.balance ?? 12345n,
    getRevision: () => over.revision ?? 7n,
  };
}

test("snapshotFromDashIdentity maps the tooling identity into a library snapshot", () => {
  const snap = snapshotFromDashIdentity(mockIdentity(), { network: "testnet", protocolVersion: 1 });
  assert.equal(snap.network, "testnet");
  assert.equal(snap.protocolVersion, 1);
  assert.deepEqual(snap.id, new Uint8Array(32).fill(9));
  assert.equal(snap.balance, 12345n);
  assert.equal(snap.revision, 7n);
  assert.equal(snap.publicKeys.length, 2);
  assert.equal(snap.publicKeys[0]?.disabled, false);
  assert.equal(snap.publicKeys[1]?.disabled, true, "getDisabledAt present means disabled");
  assert.equal(snap.publicKeys[1]?.securityLevel, 2);
});

test("the snapshot owns its bytes, so mutating the source key data does not change it", () => {
  const keyData = new Uint8Array(33).fill(2);
  const identity: DashIdentityLike = {
    getId: () => ({ toBuffer: () => new Uint8Array(32).fill(9) }),
    getPublicKeys: () => [
      { getId: () => 0, getPurpose: () => 0, getSecurityLevel: () => 0, getType: () => 0, getData: () => keyData, getDisabledAt: () => undefined },
    ],
    getBalance: () => 1n,
    getRevision: () => 1n,
  };
  const snap = snapshotFromDashIdentity(identity, { network: "testnet", protocolVersion: 1 });
  keyData.fill(0xff);
  assert.equal(snap.publicKeys[0]?.data[0], 2, "the snapshot copied the key bytes");
});

test("balance and revision are normalized to bigint from safe-integer number inputs", () => {
  const snap = snapshotFromDashIdentity(mockIdentity({ balance: 500, revision: 3 }), {
    network: "mainnet",
    protocolVersion: 2,
  });
  assert.equal(snap.balance, 500n);
  assert.equal(snap.revision, 3n);
});

test("an unsafe-integer or fractional number balance or revision is refused, not silently rounded", () => {
  assert.throws(
    () => snapshotFromDashIdentity(mockIdentity({ balance: 2 ** 60 }), { network: "testnet", protocolVersion: 1 }),
    InvalidIdentitySnapshotError,
  );
  assert.throws(
    () => snapshotFromDashIdentity(mockIdentity({ revision: 1.5 }), { network: "testnet", protocolVersion: 1 }),
    InvalidIdentitySnapshotError,
  );
});

test("a broken tooling object surfaces a typed error, not a native TypeError", () => {
  // getPublicKeys returns null: the .map would be a native TypeError without the converter's boundary.
  const broken = {
    getId: () => ({ toBuffer: () => new Uint8Array(32) }),
    getPublicKeys: () => null,
    getBalance: () => 1n,
    getRevision: () => 1n,
  } as unknown as DashIdentityLike;
  assert.throws(
    () => snapshotFromDashIdentity(broken, { network: "testnet", protocolVersion: 1 }),
    InvalidIdentitySnapshotError,
  );
  // A getter that itself throws is also translated, not left to escape natively.
  const throwing = {
    getId: () => {
      throw new Error("no id");
    },
    getPublicKeys: () => [],
    getBalance: () => 1n,
    getRevision: () => 1n,
  } as unknown as DashIdentityLike;
  assert.throws(
    () => snapshotFromDashIdentity(throwing, { network: "testnet", protocolVersion: 1 }),
    InvalidIdentitySnapshotError,
  );
  // A null identity or options object is rejected up front.
  assert.throws(
    () => snapshotFromDashIdentity(null as unknown as DashIdentityLike, { network: "testnet", protocolVersion: 1 }),
    InvalidIdentitySnapshotError,
  );
});

test("a field whose coercion throws is a typed error, not a native TypeError", () => {
  // A hostile protocolVersion whose Symbol.toPrimitive throws would make the snapshot validation throw a
  // native error while building its message. describeType avoids coercing it, so the error stays typed.
  const hostile = {
    [Symbol.toPrimitive]() {
      throw new Error("no coerce");
    },
  };
  assert.throws(
    () =>
      snapshotFromDashIdentity(mockIdentity(), {
        network: "testnet",
        protocolVersion: hostile as unknown as number,
      }),
    InvalidIdentitySnapshotError,
  );
});
