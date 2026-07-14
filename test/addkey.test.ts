import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import type * as Dashcore from "@dashevo/dashcore-lib";
import { createRawKeySigner } from "../src/index.js";
import { ensureLoaded } from "../src/adapter/protocol.js";
import type { IdentitySnapshot, NewKeyInput } from "../src/index.js";
import {
  InvalidIdentitySnapshotError,
  InvalidPrivateKeyError,
  InvalidTransitionError,
  KeySecurityLevelMismatchError,
  MissingStateError,
} from "../src/index.js";

const req = createRequire(import.meta.url);
const { PrivateKey } = req("@dashevo/dashcore-lib") as typeof Dashcore;
const wasm = req("@dashevo/wasm-dpp") as {
  default: () => Promise<unknown>;
  DashPlatformProtocol: new (entropy: { generate(): Uint8Array }) => {
    stateTransition: {
      createFromBuffer(b: Uint8Array): Promise<{
        getPublicKeysToAdd(): Array<{ getId(): number; getSignature(): Uint8Array | undefined }>;
      }>;
    };
  };
};

const rawOf = (p: InstanceType<typeof PrivateKey>) =>
  Uint8Array.from((p.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
const pubOf = (p: InstanceType<typeof PrivateKey>) => Uint8Array.from(p.toPublicKey().toBuffer() as Buffer);

const masterKey = new PrivateKey(undefined, "testnet");
const newPriv = new PrivateKey(undefined, "testnet");
const nonMasterKey = new PrivateKey(undefined, "testnet");

const IDENTITY_ID = new Uint8Array(32).fill(5);

// key id 0, AUTHENTICATION (0), MASTER (0), the key that may sign an identity update
function identity(): IdentitySnapshot {
  return {
    network: "testnet",
    protocolVersion: 1,
    id: IDENTITY_ID,
    revision: 1n,
    publicKeys: [{ id: 0, purpose: 0, securityLevel: 0, keyType: 0, disabled: false, data: pubOf(masterKey) }],
  };
}

const newKey: NewKeyInput = { id: 3, purpose: 0, securityLevel: 2, keyType: 0, privateKey: { raw: rawOf(newPriv) } };

// Read the added key and its witness back out of a signed identity-update transition.
async function addedKeyInfo(bytes: Uint8Array): Promise<{ id: number; witnessBytes: number }> {
  await wasm.default();
  const dpp = new wasm.DashPlatformProtocol({ generate: () => randomBytes(32) });
  const st = await dpp.stateTransition.createFromBuffer(bytes);
  const added = st.getPublicKeysToAdd()[0];
  if (added === undefined) throw new Error("no added key");
  return { id: added.getId(), witnessBytes: added.getSignature()?.length ?? 0 };
}

test("signAddKey builds an identity update and signs it with the master key", async () => {
  await ensureLoaded();
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signAddKey({
    identity: identity(),
    privateKey: { raw: rawOf(masterKey) },
    newKey,
    nonceContext: { identityNonce: 1n },
  });
  assert.equal(signed.transitionType, 5, "IdentityUpdate");
  assert.equal(signed.signingKeyId, 0, "signed by the master key");
  assert.ok(signed.signature.length > 0);
});

test("the signed transition carries the new key with an ownership witness", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signAddKey({
    identity: identity(),
    privateKey: { raw: rawOf(masterKey) },
    newKey,
    nonceContext: { identityNonce: 1n },
  });
  const added = await addedKeyInfo(signed.bytes);
  assert.equal(added.id, 3, "the new key id");
  assert.ok(added.witnessBytes > 0, "the new key carries a witness signature");
});

test("add-key signed by a non-master key is refused at the authorization step", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const withAuth: IdentitySnapshot = {
    ...identity(),
    // key id 1, AUTHENTICATION (0), HIGH (2), not a master key
    publicKeys: [{ id: 1, purpose: 0, securityLevel: 2, keyType: 0, disabled: false, data: pubOf(nonMasterKey) }],
  };
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: withAuth,
        privateKey: { raw: rawOf(nonMasterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    KeySecurityLevelMismatchError,
  );
});

test("a new key id that collides with an existing key is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: identity(),
        privateKey: { raw: rawOf(masterKey) },
        newKey: { ...newKey, id: 0 }, // collides with the master key id
        nonceContext: { identityNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a non-ECDSA new key type is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: identity(),
        privateKey: { raw: rawOf(masterKey) },
        newKey: { ...newKey, keyType: 1 }, // BLS, not supported in v1
        nonceContext: { identityNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a missing identity revision is a MissingStateError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const { revision: _omit, ...noRevision } = identity();
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: noRevision,
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    MissingStateError,
  );
});

test("no identity nonce and no transport is a MissingStateError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () => signer.signAddKey({ identity: identity(), privateKey: { raw: rawOf(masterKey) }, newKey }),
    MissingStateError,
  );
});

test("the identity nonce is drawn from a configured transport", async () => {
  let asked = false;
  const signer = createRawKeySigner({
    network: "testnet",
    transport: {
      async broadcast() {
        return { transitionHash: new Uint8Array(0), accepted: true };
      },
      async getIdentityNonce() {
        asked = true;
        return 4n;
      },
      async getIdentityContractNonce() {
        return 0n;
      },
    },
  });
  const signed = await signer.signAddKey({ identity: identity(), privateKey: { raw: rawOf(masterKey) }, newKey });
  assert.equal(asked, true, "the identity nonce should be read");
  assert.equal(signed.transitionType, 5);
});

test("an invalid new-key private key surfaces a typed error from the second decode", async () => {
  // The master decode succeeds and the new-key decode throws; the nested finally in the flow still zeroes
  // the master scalar (a structural guarantee this exercises the path for; secret.test covers the zeroing).
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: identity(),
        privateKey: { raw: rawOf(masterKey) },
        newKey: { ...newKey, privateKey: { raw: new Uint8Array(31) } },
        nonceContext: { identityNonce: 1n },
      }),
    InvalidPrivateKeyError,
  );
});

test("a fractional or out-of-range new key id is rejected before the tooling truncates it", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  for (const badId of [0.5, 4294967296, -1, Number.NaN]) {
    await assert.rejects(
      () =>
        signer.signAddKey({
          identity: identity(),
          privateKey: { raw: rawOf(masterKey) },
          newKey: { ...newKey, id: badId },
          nonceContext: { identityNonce: 1n },
        }),
      InvalidTransitionError,
      `new key id ${badId} should be rejected`,
    );
  }
});

test("an existing key id above the unsigned 32-bit range is rejected, not silently truncated", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const badIdentity: IdentitySnapshot = {
    ...identity(),
    // the master registration carries an id the tooling would truncate to 0
    publicKeys: [{ id: 4294967296, purpose: 0, securityLevel: 0, keyType: 0, disabled: false, data: pubOf(masterKey) }],
  };
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: badIdentity,
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
});

test("a revision or nonce outside the unsigned 64-bit range is rejected, not wrapped", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const call = (over: Partial<{ revision: bigint; identityNonce: bigint }>) =>
    signer.signAddKey({
      identity: { ...identity(), ...(over.revision !== undefined ? { revision: over.revision } : {}) },
      privateKey: { raw: rawOf(masterKey) },
      newKey,
      nonceContext: { identityNonce: over.identityNonce ?? 1n },
    });
  // The shared snapshot validator now catches an out-of-range revision first, with the more precise
  // snapshot error; the flow's own check still owns the increment-headroom case (in range, but no room).
  await assert.rejects(() => call({ revision: -1n }), InvalidIdentitySnapshotError);
  await assert.rejects(() => call({ revision: 2n ** 64n }), InvalidIdentitySnapshotError);
  await assert.rejects(() => call({ revision: 2n ** 64n - 1n }), InvalidTransitionError); // no room to increment
  await assert.rejects(() => call({ identityNonce: 2n ** 64n }), InvalidTransitionError);
});

test("a malformed identity snapshot is refused with a typed error, not a native TypeError", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const missingFields = { network: "testnet", protocolVersion: 1 } as unknown as IdentitySnapshot;
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: missingFields,
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
  const nonArrayKeys = { ...identity(), publicKeys: "nope" as unknown as [] };
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: nonArrayKeys,
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
});

test("a non-boolean readOnly on the new key is coerced, not passed raw to the tooling", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  const signed = await signer.signAddKey({
    identity: identity(),
    privateKey: { raw: rawOf(masterKey) },
    newKey: { ...newKey, readOnly: 1 as unknown as boolean },
    nonceContext: { identityNonce: 1n },
  });
  assert.equal(signed.transitionType, 5);
});

test("a protocol version or balance outside its integer range is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: { ...identity(), protocolVersion: 4294967296 }, // above unsigned 32-bit
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: { ...identity(), balance: 2n ** 64n }, // above unsigned 64-bit
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 1n },
      }),
    InvalidIdentitySnapshotError,
  );
});

test("a new key purpose or security level outside the unsigned 32-bit range is rejected", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: identity(),
        privateKey: { raw: rawOf(masterKey) },
        newKey: { ...newKey, purpose: 4294967296 },
        nonceContext: { identityNonce: 1n },
      }),
    InvalidTransitionError,
  );
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: identity(),
        privateKey: { raw: rawOf(masterKey) },
        newKey: { ...newKey, securityLevel: 4294967298 },
        nonceContext: { identityNonce: 1n },
      }),
    InvalidTransitionError,
  );
});

test("a non-bigint identity nonce is refused with a typed error", async () => {
  const signer = createRawKeySigner({ network: "testnet" });
  await assert.rejects(
    () =>
      signer.signAddKey({
        identity: identity(),
        privateKey: { raw: rawOf(masterKey) },
        newKey,
        nonceContext: { identityNonce: 4 as unknown as bigint },
      }),
    InvalidTransitionError,
  );
});
