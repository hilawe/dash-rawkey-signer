import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import type * as WasmDpp from "@dashevo/wasm-dpp";
import type * as Dashcore from "@dashevo/dashcore-lib";
import { signCallerTransition } from "../src/sign.js";
import { ensureLoaded, requirementFor } from "../src/adapter/protocol.js";
import type { IdentitySnapshot } from "../src/index.js";
import { KeySecurityLevelMismatchError, UnsupportedTransitionTypeError } from "../src/index.js";

const req = createRequire(import.meta.url);
/* eslint-disable @typescript-eslint/no-explicit-any */
const wasm = req("@dashevo/wasm-dpp") as any;
const { PrivateKey } = req("@dashevo/dashcore-lib") as typeof Dashcore;

const rawOf = (p: InstanceType<typeof PrivateKey>) =>
  Uint8Array.from((p.bn as unknown as { toBuffer(o: { size: number }): Buffer }).toBuffer({ size: 32 }));
const pubOf = (p: InstanceType<typeof PrivateKey>) => Uint8Array.from(p.toPublicKey().toBuffer() as Buffer);

// Build an unsigned disable-key identity-update transition authored by `identityId`, and its bytes.
async function unsignedDisableKey(identityId: unknown): Promise<Uint8Array> {
  await ensureLoaded();
  const ust = new wasm.IdentityUpdateTransition(1);
  ust.setIdentityId(identityId);
  if (typeof ust.setRevision === "function") ust.setRevision(2n);
  if (typeof ust.setIdentityContractNonce === "function") {
    try {
      ust.setIdentityContractNonce(1n);
    } catch {
      /* not applicable to this type */
    }
  }
  ust.setPublicKeyIdsToDisable(Uint32Array.from([1]));
  return Uint8Array.from(ust.toBuffer());
}

test("the requirement map fails closed for an unknown transition type", () => {
  assert.throws(() => requirementFor(999), UnsupportedTransitionTypeError);
});

test("general path signs a caller-built identity update with a raw master key and it verifies", async () => {
  await ensureLoaded();
  const master = new PrivateKey(undefined, "testnet");
  const idBytes = new Uint8Array(32).fill(7);
  const identityId = wasm.Identifier.from(Buffer.from(idBytes));

  const identity: IdentitySnapshot = {
    network: "testnet",
    protocolVersion: 1,
    id: idBytes,
    publicKeys: [{ id: 0, purpose: 0, securityLevel: 0, keyType: 0, disabled: false, data: pubOf(master) }],
  };

  const unsigned = await unsignedDisableKey(identityId);
  const signed = await signCallerTransition({ identity, privateKey: { raw: rawOf(master) }, transition: unsigned });

  assert.equal(signed.transitionType, 5, "IdentityUpdate");
  assert.equal(signed.signingKeyId, 0);
  assert.ok(signed.signature.length > 0);
  assert.deepEqual([...signed.authorId], [...idBytes]);

  // Verify by re-parsing the signed bytes and checking the signature against the master key.
  const dpp = await wasm.default().then(() => new wasm.DashPlatformProtocol());
  const reparsed = await dpp.stateTransition.createFromBuffer(Buffer.from(signed.bytes));
  const ipk = new wasm.IdentityPublicKey(1);
  ipk.setId(0);
  ipk.setType(0);
  ipk.setPurpose(0);
  ipk.setSecurityLevel(0);
  ipk.setReadOnly(false);
  ipk.setData(Buffer.from(pubOf(master)));
  assert.equal(reparsed.verifySignature(ipk, null), true);
});

test("general path refuses a non-master key for an identity update (protocol requirement enforced)", async () => {
  await ensureLoaded();
  const high = new PrivateKey(undefined, "testnet"); // will be registered at HIGH, not MASTER
  const idBytes = new Uint8Array(32).fill(9);
  const identityId = wasm.Identifier.from(Buffer.from(idBytes));

  const identity: IdentitySnapshot = {
    network: "testnet",
    protocolVersion: 1,
    id: idBytes,
    publicKeys: [{ id: 1, purpose: 0, securityLevel: 2, keyType: 0, disabled: false, data: pubOf(high) }],
  };

  const unsigned = await unsignedDisableKey(identityId);
  await assert.rejects(
    () => signCallerTransition({ identity, privateKey: { raw: rawOf(high) }, transition: unsigned }),
    KeySecurityLevelMismatchError,
  );
});
