# dash-rawkey-signer

Sign Dash Platform state transitions as an identity using a raw private key, with no
hierarchical-deterministic wallet seed.

**What this is, in plain terms.** Dash Platform is the application layer of the Dash network, where
accounts (called identities) store data and move funds by submitting signed instructions. Normally you
need the official wallet software to sign those instructions, and the wallet insists on managing your
keys its own way, generated from a seed phrase and kept inside its own structure. But plenty of real
situations hand you a key by itself, with no wallet around it. A server signing on behalf of a service.
A recovery scenario where someone reassembled a key from backup shares. A key living in a hardware
security module that only ever exports raw bytes. This library exists for exactly those situations. You
hand it the bare key and a description of the account, and it produces a correctly signed instruction,
ready to submit. It deliberately does very little else, and it is built defensively, so a wrong key, a
mismatched account, or a malformed request gets refused with a clear error instead of producing a
signature that the network would reject or, worse, one you did not intend.

The Dash SDK signs platform transitions through a wallet that owns the identity's keys inside an HD tree.
Backend services and recovery tools often hold an identity key as a standalone value instead, extracted
from a hardware module, a key-management service, or a recovery share. This library signs a transition
with that raw key directly. It owns no network client and no wallet. The caller passes an identity
snapshot and a key, and gets back signed bytes to broadcast.

Every signing path runs through one authorization step first. That step binds the key, the identity, and
the transition together, derives the required key from the protocol rather than from the caller, and
refuses a transition it cannot describe rather than signing it on a weaker check.

## Install

```
npm install dash-rawkey-signer
```

The package is ECMAScript modules only. `require()` is not supported; use `import` (Node 20 or later).

The tooling packages `@dashevo/wasm-dpp` and `@dashevo/dashcore-lib` are dependencies. The `dash` SDK is
an optional peer dependency that the library never imports. You need it only when your own transport or
identity fetching is built on the SDK, for example to read nonces and broadcast online, or to fetch the
identity you pass to `snapshotFromDashIdentity`.

## Quick start

```ts
import { createRawKeySigner } from "dash-rawkey-signer";

const signer = createRawKeySigner({ network: "testnet" });

const signed = await signer.signWithdrawal({
  identity,                       // an IdentitySnapshot (see below)
  privateKey: { raw: keyBytes },  // 32 raw bytes, or { wif: "..." }
  toAddress: "yjT...",            // a Dash core address
  amount: 100000n,               // credits, as a bigint
  nonceContext: { identityNonce: 4n },
});

// signed.bytes is the serialized, signed transition, ready to broadcast.
```

The protocol WebAssembly loads lazily on the first operation, which blocks the event loop noticeably
once. A backend service that prefers to take that hit at startup can call the exported `initialize()`
ahead of traffic; it is optional and idempotent.

A signer holds network and transport configuration but never a private key. Each call takes the key, so
no long-lived object owns a secret.

## The identity snapshot

The library never fetches your account from the network. You describe it yourself, in a small plain
object, and everything is checked against that description.

The core accepts a library-owned `IdentitySnapshot`, not a tooling identity object, so a tooling version
change stays contained to this library. Build one from a fetched identity, or assemble it directly for
offline use.

```ts
import { snapshotFromDashIdentity } from "dash-rawkey-signer";

// From a dash SDK identity (fetched via platform.identities.get):
const identity = snapshotFromDashIdentity(fetchedIdentity, {
  network: "testnet",
  protocolVersion: platform.protocolVersion,
});
```

Assembled directly, a snapshot is:

```ts
const identity = {
  network: "testnet",
  protocolVersion: 1,            // your platform's protocol version (platform.protocolVersion after init)
  id: identityIdBytes,           // 32 bytes
  publicKeys: [
    { id: 0, purpose: 0, securityLevel: 0, keyType: 0, disabled: false, data: masterPubKeyBytes },
    { id: 1, purpose: 0, securityLevel: 2, keyType: 0, disabled: false, data: authPubKeyBytes },
  ],
  balance: 187846616210n,        // credits, used for the withdrawal preflight
  revision: 3n,                  // required by identity-update flows (add-key)
};
```

Purpose, security level, and key type mirror the protocol's enumerations. `KeyPurpose`,
`KeySecurityLevel`, and `KeyType` are exported for reference.

A directly assembled snapshot can be checked up front with the exported `validateIdentitySnapshot(identity)`,
which throws a typed `InvalidIdentitySnapshotError` naming the first defect (an unknown network, an
out-of-range integer, a duplicate key id). Every signing operation runs the same validation internally, so
calling it yourself is optional and just fails earlier with the same error.

## Hand-held flows

Each hand-held flow builds a transition through the tooling and then joins the same authorization and
signing path, so the guarantees hold identically to the general path.

### Documents

`signDocumentBatch` builds a documents-batch transition from a discriminated action list. A create
carries the document data, a replace carries the existing document id, its current revision, and the new
data, and a delete carries the target id. The signing key is checked against the contract's per-document
security requirement, not just the protocol default. Document properties are not validated against the
contract's schema before signing; malformed data is caught by the network at broadcast, not locally.

```ts
const signed = await signer.signDocumentBatch({
  identity,
  privateKey: { raw: authKeyBytes },
  contract: serializedContractBytes,   // the data contract, as bytes
  actions: [
    { action: "create", documentType: "note", data: { message: "recovered" } },
    { action: "replace", documentType: "note", id: existingDocId, revision: 1n, data: { message: "edited" } },
    { action: "delete", documentType: "note", id: staleDocId },
  ],
  nonceContext: { contractNonce: 5n },
});
```

### Credit withdrawal

`signWithdrawal` builds a credit-withdrawal transition. The core fee rate defaults to the protocol floor
of 1 rather than a zero a fresh wallet would report, and it is validated against the protocol's allowed
sequence. When the snapshot carries a balance, the amount is checked against it before signing.

```ts
const signed = await signer.signWithdrawal({
  identity,
  privateKey: { wif: transferKeyWif },
  toAddress: "yjT...",
  amount: 100000n,
  coreFeeRate: 1,                // optional; defaults to the protocol floor
  nonceContext: { identityNonce: 4n },
});
```

### Add a key

`signAddKey` adds a new public key to an identity through an identity-update transition. Two keys take
part. The new key signs its own ownership witness, which proves possession, and the identity's master key
signs the transition. Supply the new key with its own private key, and the library derives its public
bytes and signs the witness. This flow needs the identity's current `revision`.

```ts
const signed = await signer.signAddKey({
  identity,                              // must include revision
  privateKey: { raw: masterKeyBytes },   // the master key, signs the transition
  newKey: {
    id: 3,
    purpose: 0,                          // authentication
    securityLevel: 2,                    // high
    keyType: 0,                          // ECDSA secp256k1
    privateKey: { raw: newKeyBytes },    // signs the ownership witness
  },
  nonceContext: { identityNonce: 5n },
});
```

## General path

`signTransition` signs an already-constructed transition whose key requirement the protocol defines,
parsing it and enforcing that requirement. It refuses a transition type it cannot describe, and it refuses
a documents-batch transition specifically, because that transition's key requirement depends on the data
contract, which the general path does not have. Route document writes through `signDocumentBatch` instead.
The transition arrives already constructed, so its nonce and revision are the caller's responsibility on
this path; the hand-held flows manage them for you.

```ts
const signed = await signer.signTransition({ identity, privateKey: { raw: keyBytes }, transition: builtBytes });
```

## Broadcast, authorize, and a bound key

Signing and submitting are separate on purpose, so you can sign on one machine and submit from another.
`broadcast` parses the input before transport, so a stray byte array is rejected rather than transmitted.
It needs a configured transport.

```ts
const result = await signer.broadcast(signed);   // { transitionHash, accepted }
```

`authorize` is a read-only possession and authorization check. It resolves the key that would sign and
unlocks nothing.

```ts
const info = await signer.authorize({ identity, privateKey: { raw: keyBytes }, transition: builtBytes });
```

`withKey` binds one key for repeated general-path operations during a single-key recovery, and zeroes it
on dispose.

```ts
const bound = signer.withKey({ raw: keyBytes });
const a = await bound.signTransition({ identity, transition: firstBytes });
const b = await bound.signTransition({ identity, transition: secondBytes });
bound.dispose();
```

## Online and offline

The library owns no network client. For online flows, inject a transport that wraps your `dash` SDK
client. The library uses it to read the current nonce and to broadcast.

```ts
const transport = {
  async broadcast(bytes) { /* dapiClient.platform.broadcastStateTransition(bytes), then wait */ },
  async getIdentityNonce(identityId) { /* current identity nonce */ },
  async getIdentityContractNonce(identityId, contractId) { /* current per-contract nonce */ },
};
const signer = createRawKeySigner({ network: "testnet", transport });
```

For offline signing, supply the nonce through `nonceContext` and omit the transport. Withdrawal and
add-key use `identityNonce`, and documents use `contractNonce`. Add-key also needs the identity's current
`revision` in the snapshot.

The default nonce source serializes allocation within the process, so two concurrent sign calls receive
distinct successive nonces. A backend running several instances against the same identities should
inject its own `NonceSource` backed by whatever coordination it already runs (a database sequence, a
distributed lock or cache), implementing `nextIdentityNonce` and `nextIdentityContractNonce` to hand out
values serialized across instances. A cross-process conflict is detected by the network at broadcast, where the
injected transport surfaces the network's rejection. The library exports `NonceConflictError`, carrying
the observed nonce, for a transport to raise on a retryable conflict, but it does not translate SDK errors
itself, so mapping them is the transport's responsibility. A transport that maps its SDK failures into the
exported error classes (`BroadcastError`, `NetworkError`, `NonceConflictError`) gives its callers precise
types to branch on. Anything else it throws still surfaces as a typed `UnexpectedError` through the
library's error boundary, just less specifically.

## Security model

- One authorization step precedes every signature. It requires the transition's author to equal the
  identity, matches the supplied key by its public bytes, resolves it to a single key id that becomes the
  transition's signing-key id, and enforces the purpose and security level the protocol requires for that
  transition. For a documents batch, the security level is read from the contract and enforced, since the
  tooling does not enforce it at signing in this build.
- A raw private key is decoded into the secret boundary, which holds the signing scalar as one owned
  buffer, exposes it only to the signing callback, and zeroes it on dispose. The add-key flow decodes two
  keys and zeroes both scalars on every path, and the document flow also zeroes the raw-key copy it makes
  for the time-of-check guard. `withKey` zeroes the raw bytes it was given when disposed. The caller's own
  key buffer is otherwise theirs to manage, and an immutable WIF string cannot be erased from the caller's
  heap, so prefer raw bytes for long-lived secrets.
- The library's own errors are typed. Every failure a caller can branch on extends `RawKeySignerError`
  and carries a stable `code`, and none carries private key material. Every public method also translates
  any unexpected native error into an `UnexpectedError`, which keeps only the thrown value's `typeof`, so a
  native `TypeError` or a raw tooling string never escapes and no thrown object is retained. Message text is
  human-readable and is not part of the compatibility promise.
- The no-key-material guarantee covers errors the library constructs. A value thrown by caller-supplied code
  that the library invokes (a transport, an identity getter passed to `snapshotFromDashIdentity`, a byte
  iterator) is relayed with its type when it is one of these error classes, so do not attach a private key
  to an error you throw into a signer callback, the same trust the library extends to a transport's own
  error contents. The library itself never attaches key material to an error it builds.
- Every integer the library passes to the tooling is range-checked first (key ids and related fields as
  unsigned 32-bit, nonces, revisions, balances, and amounts as unsigned 64-bit), because the tooling's
  WebAssembly setters silently wrap out-of-range values.

## Errors

Branch by `instanceof` or by the stable `code`.

```ts
import { KeySecurityLevelMismatchError, NonceConflictError } from "dash-rawkey-signer";

try {
  await signer.signAddKey({ /* ... */ });
} catch (err) {
  if (err instanceof KeySecurityLevelMismatchError) { /* not a master key */ }
}
```

## Compatibility

| Component | Version |
| --- | --- |
| Node.js | >= 20 |
| `@dashevo/wasm-dpp` | 4.0.0 |
| `@dashevo/dashcore-lib` | ^0.22.0 |
| `dash` (optional peer) | ^7.0.0 |
| Dash Platform protocol | set by the caller; conformance-tested at versions 1 and 12, live-verified at 1 |

Upgrading `@dashevo/wasm-dpp` is never a routine dependency bump. The adapter reaches into that
package's specific export shapes and setter behavior, so any version change requires re-validating the
whole WebAssembly bridge (the 0.2.0 conformance matrix in the repository's TODO is the intended gate).

The protocol version is a field on the identity snapshot, so the library works across the versions the
tooling supports. It is exercised offline at versions 1 and 12, and the pinned `@dashevo/wasm-dpp` 4.0.0
reports 12 as its latest, which `dash` 7 uses by default. Set `protocolVersion` to your platform's version
(`platform.protocolVersion` after the SDK initializes). The tooling pins `@dashevo/wasm-dpp` to an exact
version, because a protocol version change can alter the serialized transition format. The library signs
ECDSA secp256k1 keys.

## Versioning

This package follows semantic versioning. While the version is below 1.0.0 the public API may change in a
minor release, and each such change is called out in the changelog. The public surface under the
compatibility promise is the exported functions and types, the error classes and their `code` values, and
the shape of the `IdentitySnapshot` and `SignedTransition`. Error message text and internal module paths
are not part of that promise.

## License

MIT.
