# TODO, dash-rawkey-signer

Seeded from the clean-room design round and updated after the architectural review. The gates come
before implementation. The v1 build follows `DESIGN.md` section 12. The deferred and roadmap items are
the divergences and novel ideas kept out of v1, revisited on the stated evidence.

## Gates before implementation

- [x] Architectural review of `DESIGN.md` by three independent models. Verdicts: two approve-with-fixes,
  one reject on the strict "an invariant is false as written" standard, architecture sound in all three.
  Every confirmed and fact-checked finding is folded into the current `DESIGN.md`.
- [x] Focused re-check: confirm the revised `DESIGN.md` resolves the review's blockers (fail-closed
  requirement derivation, author and signing-key binding, general-path nonce validation, broadcast input
  validation, richer document input, fee-rate default, secret boundary, the nonce seam). One independent
  pass naming the findings and asking whether each is resolved.
- [x] Phase 0 spike, the riskiest assumptions. Build a document, an add-key, and a disable-key
  transition, and a withdrawal with fee handling, sign each with a raw key, verify offline, and broadcast
  to a local devnet. Drive a caller-constructed transition through the general path. Add negative
  fixtures (wrong author, wrong signing-key id, wrong nonce scope, insufficient key security) and confirm
  the library refuses them before signing. Blocks all further work.

## v1 build (after the spike passes, per DESIGN.md section 12)

- [x] Core: the authorization step with full binding (author id, unique key resolution, signing-key id,
  re-parse), fail-closed requirement derivation, the internal signing primitive, the typed errors, and
  the secret boundary with scalar and WIF-byte zeroing.
- [x] The adapter split into protocol and transport operations, with conformance fixtures, and the
  injectable nonce source with its simple default and retry affordance.
- [x] Hand-held flows with the discriminated document input (create, replace, delete evidence), nonce
  validation on every path, fee-rate defaulting to the protocol floor, and the balance preflight.
- [ ] The general `signTransition` path and `broadcast` with input parsing and broadcast-elsewhere
  verification.
- [ ] Offline construction with an explicit nonce context and the staleness gate, the optional bound
  view (`withKey`), and the multi-party pattern documented.
- [ ] The manual devnet check, then release with semantic-versioning rules and a compatibility table.

## Deferred divergences (revisit with evidence)

- [ ] A cross-process or distributed nonce lease behind the injectable seam. The seam and an in-process
  reservation ship in v1. A lease spanning processes or hosts is deferred until a distributed
  multi-signer deployment is a real use.
- [ ] A multi-party planning and routing helper that assigns each transition to the right key holder.
- [ ] An auto-detecting create-or-replace resolver that performs the unique-index lookup and returns a
  create or replace plan, on top of the explicit document input.
- [ ] A contract-aware authorization preflight for documents batches (a release-review idea). `authorize`
  refuses DocumentsBatch because computing the exact security level needs the data contract. An
  `authorizeWithContracts` variant accepting serialized contracts alongside the transition would let a
  coordinator run the preflight without spoofing a signing flow. The adapter pieces (`loadContract`,
  `documentSecurityLevels`) already exist; revisit when a multi-party coordinator is a real use.

- [ ] Serialization helpers for air-gapped transport (a release-review idea). `snapshotToJson` and
  `snapshotFromJson` (and the same for `SignedTransition`), a canonical JSON form with byte fields as hex,
  so recovery workflows ferrying snapshots to an air-gapped signer over QR or USB do not each write their
  own byte mapper. Revisit when an air-gapped consumer exists.
- [ ] An optional retry policy on the default nonce source (a release-review idea). Transient transport
  timeouts fail the allocation today; a bounded, jittered retry would absorb them. Revisit with evidence
  from a production transport.

- [ ] A thin prebuilt transport wrapper over the dash SDK (a release-review idea). The Transport seam
  stays, and a `createDashTransport(client)` helper forwards the three methods and maps SDK errors, so the
  common online case is one line. Verify the SDK surface first; revisit on the first real online consumer.
- [ ] An in-memory nonce source for tests and offline tooling (a release-review idea), reusing the default
  source's allocation logic over a plain Map, so nonce behavior is drivable without a transport.

## 0.2.0 (next planned release)

- [ ] The protocol conformance matrix, the holistic review's highest-confidence test class. Every
  transition family at every claimed protocol version (1 and 12), stable parsed fields, sign and
  re-parse, signature verification where the tooling exposes it, wrong nonce and scope negatives, and
  concurrent allocation through a contract transport. Widening the README compatibility claim beyond
  version 1 waits on this matrix passing.

## Novel hardening ideas (roadmap)

- [ ] Broaden the wasm-boundary input validation over time as new panic modes are found. The adapter's
  structural extraction of the CommonJS wasm package (the default-export loader, the class constructors)
  is the project's highest-risk bit-rot vector: a tooling move to native ESM or a new wasm bundling shape
  fails at startup. On the next tooling upgrade, verify the extraction first, and consider a specific
  initialization error naming which export shape failed.
- [ ] npm provenance for future releases. Requires publishing from CI with OIDC, so it lands together
  with the repository going public and gaining a release workflow.
- [ ] Offline freshness tooling (state basis, capture metadata, the high-risk gate). Deferred entirely; the v1 types shipped without an implementation and were removed pre-publish (see DESIGN section 8 note).
- [ ] Blessed hand-held methods for the higher-risk identity updates (disable, rotate), each after its
  own threat-modeling, replacing the general-path route for the common cases.
