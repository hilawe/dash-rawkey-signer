# Changelog

## 0.3.2 (2026-07-14)

Documentation only. The README intro is restructured for readability (a short-version one-liner, the
plain-terms explainer in short paragraphs, and the redundant technical intro paragraph removed in favor
of the SDK-fit section). No code changes.

## 0.3.1 (2026-07-14)

A consumer-confirmed fix. Byte views (Buffer, Uint8Array) in document data now normalize to plain number
arrays in the clone, because the tooling's conversion layer encodes a typed array as an index-keyed map
in the serialized transition, which the network's validator rejects for byteArray fields while accepting
the compact form a plain array produces. Signing succeeded either way, so only a broadcast exposed the
difference: the first real consumer's stack trace localized the rejection to broadcast, and comparing
serialized bytes confirmed the divergence (400-byte map-form transitions from typed arrays versus 250
bytes from arrays). All representations now serialize identically, pinned by test.

## 0.3.0 (2026-07-14)

- `createDashTransport(client)`: wrap a configured dash SDK client into the library's Transport in one
  line. Forwards the nonce reads, broadcasts with a proof-backed result wait, and maps SDK failures into
  the exported error classes. The SDK stays an optional peer the library never imports; the client is
  read structurally. Hardened through a two-round adversarial review: the error model is phase-aware
  and gRPC-code-aware (transport codes 4 and 14 and code-less throws are NetworkError with indeterminate
  delivery, other coded rejections are BroadcastError with the platform code, post-delivery wait failures
  are NetworkError with indeterminate delivery false), and every boundary contains hostile input.
- byteArray document properties are pinned end to end in all three representations (Buffer, Uint8Array,
  plain array), a coverage gap reported by the first real consumer. The reported failure does not
  reproduce on the pinned tooling; consuming the published package avoids the version skew that likely
  caused it.

All notable changes to dash-rawkey-signer. The versioning policy is in the README's Compatibility
section. Until 1.0.0, breaking changes may land in minor releases and each one is called out here.

## 0.2.0 (2026-07-14)

- The protocol conformance matrix: every transition family builds, signs, and re-parses with stable
  fields at protocol versions 1 and 12, with signature verification where the tooling exposes it,
  wrong-nonce negatives per family, and concurrent nonce allocation through a transport. The
  compatibility claim widens to name both versions on the strength of this matrix.
- The README opens with a plain-terms explainer and a section on how the library composes with the Dash
  Platform JS SDK (the SDK fetches and broadcasts, this signs), naming createDashTransport as the next
  planned feature.

## 0.1.2 (2026-07-14)

The first release published from CI with npm provenance, from the now-public repository
(github.com/hilawe/dash-rawkey-signer). Also:

- package.json gains repository, bugs, and homepage, and SECURITY.md ships the reporting channel.

- Node.js floor raised to 20. The protocol WebAssembly traps on Node 18 (end of life since 2025) in the
  documents path, caught by the public CI matrix.

## 0.1.1 (2026-07-14)

Holistic-review fixes. One behavior change: the signer's configured network is now enforced, so any
key-bearing operation refuses an identity snapshot whose network differs from the signer's (previously
the option was accepted but never checked). Also in this release:

- The LICENSE file ships (MIT was declared without its text), and `src/` ships so source maps resolve.
- README discloses that the package is ESM only, that document properties are not schema-validated
  before signing, and that nonce and revision correctness on the general path rest with the caller.
- The protocol compatibility claim is narrowed to version 1 (the devnet-verified path) until the 0.2.0
  conformance matrix widens it.
- A concurrency regression test pins the default nonce source's serialization.

## 0.1.0 (2026-07-14)

The first published release.

- The general signing path (`signTransition`), the read-only `authorize`, `broadcast`, and the bound
  `withKey` view.
- Hand-held flows for documents batches (`signDocumentBatch`), credit withdrawals (`signWithdrawal`),
  and adding a key with its ownership witness (`signAddKey`).
- The `snapshotFromDashIdentity` converter, the exported `validateIdentitySnapshot` and
  `snapshotIdentity` helpers, and the optional `initialize()` warm-up.
- A typed error hierarchy behind a total error boundary, a secret boundary that zeroes key material on
  every path, single-read snapshotting of every caller-owned input before any await, and range checks on
  every integer that reaches the protocol tooling.
