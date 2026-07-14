import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createDashTransport, createRawKeySigner, snapshotFromDashIdentity } from "../src/index.js";
import { BroadcastError, ClientRequiredError, NetworkError } from "../src/index.js";
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

// --- createDashTransport ---

function fakeSdkClient(over: Partial<{
  broadcastThrows: unknown;
  waitError: { code?: number; message?: string };
  identityNonce: unknown;
  contractNonce: unknown;
}> = {}) {
  const calls: { broadcast: Uint8Array[]; nonceIds: Uint8Array[] } = { broadcast: [], nonceIds: [] };
  const platform = {
    async broadcastStateTransition(bytes: Uint8Array) {
      if (over.broadcastThrows !== undefined) throw over.broadcastThrows;
      calls.broadcast.push(bytes);
    },
    async waitForStateTransitionResult() {
      return over.waitError ? { error: over.waitError } : {};
    },
    async getIdentityNonce(id: Uint8Array) {
      calls.nonceIds.push(id);
      return { identityNonce: over.identityNonce !== undefined ? over.identityNonce : 41n };
    },
    async getIdentityContractNonce() {
      return { identityContractNonce: over.contractNonce !== undefined ? over.contractNonce : 7 };
    },
  };
  return { client: { getDAPIClient: () => ({ platform }) }, calls };
}

test("createDashTransport forwards the nonce reads and normalizes to bigint", async () => {
  const { client } = fakeSdkClient();
  const transport = createDashTransport(client as never);
  assert.equal(await transport.getIdentityNonce(new Uint8Array(32)), 41n);
  assert.equal(await transport.getIdentityContractNonce(new Uint8Array(32), new Uint8Array(32)), 7n);
});

test("createDashTransport broadcast returns the sha256 hash and accepted on a clean result", async () => {
  const { client, calls } = fakeSdkClient();
  const transport = createDashTransport(client as never);
  const bytes = new Uint8Array([1, 2, 3]);
  const out = await transport.broadcast(bytes);
  assert.equal(out.accepted, true);
  assert.equal(out.transitionHash.length, 32);
  assert.deepEqual(calls.broadcast[0], bytes, "the signed bytes reach the SDK");
});

test("a platform rejection maps to BroadcastError with the platform code", async () => {
  const { client } = fakeSdkClient({ waitError: { code: 40, message: "nonce out of bounds" } });
  const transport = createDashTransport(client as never);
  const err = (await transport.broadcast(new Uint8Array([1])).then(
    () => null,
    (e) => e,
  )) as InstanceType<typeof BroadcastError>;
  assert.ok(err instanceof BroadcastError);
  assert.equal(err.platformCode, 40);
  assert.ok(err.transitionHash && err.transitionHash.length === 64, "the hash rides the error as hex");
});

test("a transport-level throw maps to NetworkError with indeterminate delivery", async () => {
  const { client } = fakeSdkClient({ broadcastThrows: new Error("grpc deadline exceeded") });
  const transport = createDashTransport(client as never);
  const err = (await transport.broadcast(new Uint8Array([1])).then(
    () => null,
    (e) => e,
  )) as InstanceType<typeof NetworkError>;
  assert.ok(err instanceof NetworkError);
  assert.equal(err.indeterminateDelivery, true);
});

test("an invalid SDK nonce shape is a typed NetworkError, and a bad client is refused at creation", async () => {
  const { client } = fakeSdkClient({ identityNonce: "not-a-nonce" });
  const transport = createDashTransport(client as never);
  await assert.rejects(() => transport.getIdentityNonce(new Uint8Array(32)), NetworkError);
  assert.throws(() => createDashTransport(null as never), ClientRequiredError);
  assert.throws(() => createDashTransport({} as never), ClientRequiredError);
});

test("the one-line pairing works: a signer over createDashTransport draws its nonce through the SDK", async () => {
  const { client } = fakeSdkClient({ identityNonce: 3n });
  const req2 = createRequire(import.meta.url);
  const { PrivateKey } = req2("@dashevo/dashcore-lib") as typeof import("@dashevo/dashcore-lib");
  const key = new PrivateKey(undefined, "testnet");
  const raw = Uint8Array.from((key.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
  const pub = Uint8Array.from(key.toPublicKey().toBuffer() as Buffer);
  const signer = createRawKeySigner({ network: "testnet", transport: createDashTransport(client as never) });
  const signed = await signer.signWithdrawal({
    identity: {
      network: "testnet",
      protocolVersion: 1,
      id: new Uint8Array(32).fill(2),
      balance: 1_000_000_000n,
      publicKeys: [{ id: 0, purpose: 3, securityLevel: 1, keyType: 0, disabled: false, data: pub }],
    },
    privateKey: { raw },
    toAddress: new PrivateKey(undefined, "testnet").toAddress("testnet").toString(),
    amount: 1000n,
  });
  assert.equal(signed.transitionType, 6, "signed with the nonce drawn through the SDK transport");
});

test("the broadcast hash is exactly the sha256 of the signed bytes, matching the SDK's discipline", async () => {
  const { createHash } = await import("node:crypto");
  const { client } = fakeSdkClient();
  const transport = createDashTransport(client as never);
  const bytes = new Uint8Array([9, 8, 7, 6]);
  const out = await transport.broadcast(bytes);
  assert.deepEqual(out.transitionHash, Uint8Array.from(createHash("sha256").update(bytes).digest()));
});

test("a code-carrying throw at submission is a platform rejection, not a network failure", async () => {
  const grpcStyle = Object.assign(new Error("invalid transition"), { code: 3 });
  const { client } = fakeSdkClient({ broadcastThrows: grpcStyle });
  const transport = createDashTransport(client as never);
  const err = (await transport.broadcast(new Uint8Array([1])).then(
    () => null,
    (e) => e,
  )) as InstanceType<typeof BroadcastError>;
  assert.ok(err instanceof BroadcastError, "a rejection at the door is a BroadcastError");
  assert.equal(err.platformCode, 3);
});

test("a wait-phase failure after acknowledged delivery is not flagged as indeterminate delivery", async () => {
  const { client } = fakeSdkClient();
  const platform = (client.getDAPIClient() as { platform: { waitForStateTransitionResult: unknown } }).platform;
  platform.waitForStateTransitionResult = async () => {
    throw new Error("stream reset");
  };
  const transport = createDashTransport(client as never);
  const err = (await transport.broadcast(new Uint8Array([1])).then(
    () => null,
    (e) => e,
  )) as InstanceType<typeof NetworkError>;
  assert.ok(err instanceof NetworkError);
  assert.equal(err.indeterminateDelivery, false, "delivery was acknowledged; only the result is unknown");
});

test("a malformed SDK broadcast result is a typed NetworkError, and hostile byte subclasses are memcpy-copied", async () => {
  const { client } = fakeSdkClient();
  const platform = (client.getDAPIClient() as { platform: { waitForStateTransitionResult: unknown } }).platform;
  platform.waitForStateTransitionResult = async () => "garbage";
  const transport = createDashTransport(client as never);
  await assert.rejects(() => transport.broadcast(new Uint8Array([1])), NetworkError);
  // A subclass with a throwing iterator must not reach the SDK or throw natively; set() ignores it.
  class Hostile extends Uint8Array {
    [Symbol.iterator](): IterableIterator<number> {
      throw new Error("hostile iterator");
    }
  }
  const clean = fakeSdkClient();
  const t2 = createDashTransport(clean.client as never);
  assert.equal(await t2.getIdentityNonce(new Hostile(32)), 41n);
});

test("a gRPC transport code at submission (deadline, unavailable) is a NetworkError, not a rejection", async () => {
  for (const code of [4, 14]) {
    const { client } = fakeSdkClient({ broadcastThrows: Object.assign(new Error("transport"), { code }) });
    const transport = createDashTransport(client as never);
    const err = (await transport.broadcast(new Uint8Array([1])).then(
      () => null,
      (e) => e,
    )) as InstanceType<typeof NetworkError>;
    assert.ok(err instanceof NetworkError, `code ${code} is a transport failure`);
    assert.equal(err.indeterminateDelivery, true);
  }
});

test("a result whose error getter throws is contained as a typed NetworkError, not a native escape", async () => {
  const { client } = fakeSdkClient();
  const platform = (client.getDAPIClient() as { platform: { waitForStateTransitionResult: unknown } }).platform;
  platform.waitForStateTransitionResult = async () =>
    Object.defineProperty({}, "error", {
      get() {
        throw new Error("hostile error getter");
      },
    });
  const transport = createDashTransport(client as never);
  await assert.rejects(() => transport.broadcast(new Uint8Array([1])), NetworkError);
});

test("a broadcast input with a throwing byteLength is contained, before anything is sent", async () => {
  let sent = false;
  const { client } = fakeSdkClient();
  const platform = (client.getDAPIClient() as { platform: { broadcastStateTransition: unknown } }).platform;
  platform.broadcastStateTransition = async () => {
    sent = true;
  };
  const transport = createDashTransport(client as never);
  class BadLength extends Uint8Array {
    get byteLength(): number {
      throw new Error("hostile byteLength");
    }
  }
  const err = (await transport.broadcast(new BadLength(4)).then(
    () => null,
    (e) => e,
  )) as InstanceType<typeof NetworkError>;
  assert.ok(err instanceof NetworkError);
  assert.equal(sent, false, "nothing was submitted");
  assert.equal(err.indeterminateDelivery, false, "nothing was sent, so delivery is not indeterminate");
});
