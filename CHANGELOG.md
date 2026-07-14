# Changelog

All notable changes to dash-rawkey-signer. The versioning policy is in the README's Compatibility
section. Until 1.0.0, breaking changes may land in minor releases and each one is called out here.

## Unreleased

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
