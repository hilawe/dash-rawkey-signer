# Design, dash-rawkey-signer

The design for a small, publishable TypeScript library that signs Dash Platform state transitions on
behalf of an identity using a raw private key, with no hierarchical-deterministic (HD) wallet seed.

This document is the synthesis of a clean-room design round, revised after an independent architectural
review. Three frontier models from families other than the author each produced a full design from the
architecture-free requirements alone (an architecture-free requirements packet, kept in the private project record). Three models then reviewed this
document. The review found the architecture sound but several enforcement invariants under-specified, so
this revision pins them down. Choices the independent designs converged on are marked FORCED. Choices
where they diverged are marked CHOSEN, with the reason and the rejected alternative. Acronyms: SDK
(software development kit), DPP (Dash Platform Protocol), WIF (wallet import format), L1 (the Dash
layer-1 chain), wasm (WebAssembly).

## 1. Shape

A `RawKeySigner`, created through a factory, is the public entry point. It holds transport and network
configuration only. It never holds a private key. Every operation takes the identity and the raw key,
so no long-lived object owns a secret. An optional bound view (`signer.withKey(privateKey)`) carries one
key for the common single-key flow and is explicitly disposed.

Three surfaces sit on the signer:

1. Hand-held methods for the v1 transition families (documents, credit withdrawal, add-key).
2. One general path, `signTransition`, that signs any already-constructed transition, including types
   with no hand-held method and future types, under the same enforced invariants.
3. `broadcast`, which parses and validates a signed transition (from this signer or elsewhere) and
   submits it.

Every signing path passes through one authorization step first. That step is the security core.

## 2. Decisions

### Forced by the requirements

- F1. One authorization step precedes every signature, and the signing primitive is internal and
  unreachable without it. The step binds the key, the identity, and the transition together (see
  section 4). Serves R4 and R6.
- F2. The required key purpose and security level are derived from the parsed transition at the
  protocol's own granularity (its type and, where the protocol's requirement depends on it, its
  action or variant), never supplied by the caller. If the adapter cannot derive an authoritative
  requirement for a transition, the library fails closed and refuses to sign. Serves C2, R4, and F3.
- F3. The general path signs any caller-constructed transition through the same binding, secret, and
  nonce invariants as the hand-held methods. It is not a way to relax any of them. A transition whose
  requirement the library cannot derive is refused, not signed on a weaker check. Serves R3 and R6.
- F4. The library composes with the existing tooling and never forks or reimplements the protocol. All
  construction, serialization, validation, and the signing primitive come from the tooling, reached
  through one internal adapter split into protocol operations and transport operations. Serves C3.
- F5. Raw keys are secrets, handled inside a defined boundary (section 5). Serves R5.
- F6. Authorization runs offline from a caller-supplied identity snapshot, and construction runs offline
  from caller-supplied surrounding state. Serves R9.
- F7. Multi-party control is several single-key signings the caller sequences, with nonce ownership made
  explicit (section 10) so the sequencing is enforceable rather than only documented. No threshold
  cryptography, no combined signatures. Serves C1 and R10.
- F8. Failures are typed and distinguishable by class and a stable `code`. Serves R11.
- F9. A credit withdrawal's core fee rate is both supplied and validated. The library supplies the
  protocol floor as a deterministic default (or a provider value, falling back to the floor when the
  value is zero or invalid), and validates it as an integer at or above the floor and in the protocol's
  allowed sequence. Serves R8.
- F10. Node.js is the v1 target, binary is `Uint8Array` at the surface, cryptography is delegated to the
  tooling, and the core avoids Node-only patterns so a browser build stays additive. Serves P1 and X3.
- F11. The automated suite runs with no live network, building transitions from fixed fixtures and
  confirming serialization, signature verification, and every authorization failure, including the
  negative binding cases. Serves C5 and R12.
- F12. The riskiest assumptions are validated by a thin end-to-end slice before the rest is built,
  including the adversarial path and negative cases (section 12). Serves the build-plan requirement.

### Chosen deliberately

- D1. The public surface is library-owned. The core accepts only a versioned library-owned
  `IdentitySnapshot`, and a separate integration helper (`snapshotFromDashIdentity`) converts a tooling
  identity into it, so a tooling change touches the helper, not the core contract. Results are a
  library-owned `SignedTransition` carrying the serialized bytes, so a caller may broadcast through the
  SDK directly if preferred. Reason: the library's value is a durable seam, and Q4 and Q6 call for
  isolating callers from the tooling's version churn, which an external-interface boundary should get
  right early. Rejected alternatives: exposing the tooling's entity types directly (simpler, but couples
  every caller to the tooling's version changes, and the review noted this only defers the isolation
  cost), and accepting both a tooling identity and a snapshot (self-contradictory, since it would put a
  tooling type in the surface). The snapshot-only core with a converter is the leanest form that still
  isolates.
- D2. Nonce handling is simple by default (acquire the current nonce and use the next value, or accept
  an explicit nonce for offline construction), with the default source serializing allocation within the
  process, typed conflict errors, a retry affordance, and an injectable seam so a cross-process lease can
  be added later without a breaking change. Reason: the majority of the designs chose simple, and two
  reviewers pressed for a full reservation-and-lease model. The design is safe as written, because the
  protocol enforces nonce ordering, so a race is rejected and retried rather than causing an invalid
  state change. The in-process reservation closes the common single-process race, and the seam keeps a
  distributed lease a non-breaking addition. A full distributed coordinator is a recorded deferral (see
  `TODO.md`) over the remaining reviewer dissent, not an unaddressed gap.
- D3. Multi-party is caller-sequenced, with nonce ownership made explicit through the D2 seam so the
  sequencing responsibility is enforceable. Reason: majority, and each transition is single-signed
  regardless. A planning and routing helper is deferred.
- D4. Create versus replace for a document is explicit, chosen by the caller, and the document input
  carries the evidence each action needs (section 3). Reason: majority, a clear typed failure over
  hidden index queries. An auto-detecting create-or-replace resolver is an optional deferred helper.
- D5. The raw key is supplied per operation by default, so the base signer holds no secret and one
  signer can act for several keys and identities. An optional bound view, `signer.withKey(privateKey)`,
  carries one key for the common single-key flow (repeated document operations during a recovery) and
  is explicitly disposed, zeroing the key. Reason: per-call keeps secrets out of instance state and
  suits operator and multi-party use, while the optional bound view answers the review's point that the
  motivating recovery flow is noisier and more error-prone when every call re-passes the key. The bound
  view holds the key only for its own lifetime, a tradeoff the caller opts into.
- D6. The per-transition requirement comes from a versioned internal requirements map with conformance
  tests against the protocol, and from a live protocol query where the tooling exposes the requirement
  directly. It is keyed at the protocol's own granularity, not a coarse family. Reason: it derives the
  requirement from the protocol, not the caller, while staying implementable. For documents the purpose is
  fixed (authentication) and the allowed security levels are read from the contract's per-type
  `signatureSecurityLevelRequirement` and intersected across the batch (strictest wins), because the
  tooling's own `getKeySecurityLevelRequirement` returns a static default in this build and neither it nor
  `sign` enforces the contract's requirement. Withdrawal and identity update keep the fixed map values.

## 3. Public surface

The signer holds no secret. Binary values are `Uint8Array`. Identity input is a library-owned snapshot.

```ts
const signer = createRawKeySigner({
  network: "testnet" | "mainnet" | "local",
  transport?,        // for nonce acquisition and broadcast in online flows
  nonceSource?,      // injectable nonce seam; defaults to a simple transport-backed source
})

type PrivateKeyInput = { wif: string } | { raw: Uint8Array }

// Convert a tooling identity (fetched via the SDK) into the library snapshot. Lives in an integration
// module so a tooling change does not touch the core contract.
snapshotFromDashIdentity(identity): IdentitySnapshot

// Hand-held flows. Each runs the full authorization step and returns a signed transition.
signer.signDocumentBatch({ identity, privateKey, contract, actions, nonceContext? }): Promise<SignedTransition>
signer.signWithdrawal({ identity, privateKey, toAddress, amount, coreFeeRate?, nonceContext? }): Promise<SignedTransition>
signer.signAddKey({ identity, privateKey, newKey, nonceContext? }): Promise<SignedTransition>

// General path. Signs any already-constructed transition, deriving and enforcing its requirement.
signer.signTransition({ identity, privateKey, transition }): Promise<SignedTransition>

// Optional bound view for the single-key common case. Holds the key until disposed.
const bound = signer.withKey(privateKey)   // bound.signDocumentBatch({ identity, actions, ... }), etc.
bound.dispose()                            // zeroes the held key

// Broadcast. Needs no key. Parses and validates the input before transport.
signer.broadcast(signed: SignedTransition | Uint8Array): Promise<SubmissionResult>

// Read-only possession and offline authorization check. Returns matched-key info or throws. Unlocks
// nothing; every sign re-runs the full step.
signer.authorize({ identity, privateKey, transition }): AuthorizedKeyInfo
```

`actions` is a discriminated list, so a batch can mix action kinds and each kind carries its own
evidence. A create carries document properties, a replace carries the existing document id and current
revision plus new data (the protocol increments the revision), and a delete carries only the target id.
The implementation dropped the delete revision this section first proposed, because the protocol's delete
transition binds no revision, so requiring one would be a false guarantee (a build-time finding, see
`src/types.ts`). Offline calls carry the data-contract snapshot and a `nonceContext`. `SignedTransition` is `{ bytes, transitionType, authorId, signingKeyId,
signature, stateBasis? }`, all library-owned. `IdentitySnapshot` carries the network, protocol version,
identity id, registered keys (id, purpose, security level, disabled state, key bytes), relevant nonce
state, and capture metadata.

## 4. Authorization step

Runs before every signature, in this order, offline when the snapshot is supplied. It binds the key, the
identity, and the transition together, which is what keeps the general path from being a bypass.

1. Decode the private key (WIF or raw) into an owned buffer inside the secret boundary and derive its
   public key bytes. On failure, `InvalidPrivateKeyError`.
2. Parse the transition through the adapter to obtain its canonical type, action or variant, author id,
   signing-key id, nonce, and nonce scope. If it cannot be parsed or described, `InvalidTransitionError`.
3. Require the transition's author id to equal the supplied identity's id. Otherwise,
   `AuthorIdentityMismatchError`.
4. Derive the required purpose and security level for the transition at the protocol's granularity
   (section 7, D6). If no authoritative requirement can be derived, `UnsupportedTransitionTypeError`
   and stop. The library never signs on a weaker check.
5. Find the registered key on the identity whose bytes match the derived public key, resolving to a
   single key record. When several matched records are equally eligible (identical bytes, purpose,
   security, and enabled state), select the lowest key id deterministically, since they are
   interchangeable for authorization and either produces a verifying signature. Raise
   `AmbiguousKeyError` only when the matches differ in a way that affects eligibility (purpose,
   security, or disabled state) and the protocol defines no unambiguous selection. No match,
   `KeyNotOnIdentityError`.
6. If the matched key's purpose differs from the requirement, `KeyPurposeMismatchError` (carrying the
   actual and required purpose and the transition type and action). If its security level differs,
   `KeySecurityLevelMismatchError`. If it is disabled, `KeyDisabledError`.
7. Set or require the transition's signing-key id to equal the matched key's id.
8. Validate the nonce (section 10) for the transition's scope.
9. Sign with the internal primitive, then re-parse the final serialized bytes and confirm the author,
   type, nonce, scope, and signing-key id are unchanged. A mismatch is an internal error, not a signed
   result.

## 5. Secret handling

The secret boundary lives in the adapter. Concrete guarantees behind F5 and R5:

- The raw key enters only through the `privateKey` argument of a sign method, never from the environment,
  files, or a configuration object.
- A WIF string is decoded internally into an owned mutable buffer and is never passed to the upstream
  tooling. The upstream tooling receives only what it needs to produce a signature.
- The sensitive values (the decoded private scalar and the WIF-decoded bytes) are zeroed in a `finally`
  path so a thrown error still zeroes them. Where the tooling exposes a way to destroy a private-key
  object it created, the library does so. Copies the tooling may make inside opaque wasm code cannot be
  guaranteed erased, and the docs say so plainly.
- No exposed object has a private-key field. The signer holds transport and network config only, and a
  bound view holds its key until `dispose`.
- Upstream exceptions are replaced with sanitized typed errors, and their `cause` is not exposed, so an
  input value cannot leak through an error message or debug output. Results and errors carry only
  identifiers.
- `broadcast` parses its input before transport, so a stray byte array (including a private-key buffer
  passed by mistake) is rejected rather than transmitted.
- The suite asserts that known fixture secret bytes and WIF strings appear in no observable output.
- R5 is met as a non-persistence and non-disclosure contract with owned-buffer zeroing. It does not
  claim to defend a compromised process, and it cannot erase an immutable WIF string from the caller's
  heap. Backend custody callers should prefer raw bytes in a buffer they clear.

## 6. Error model

```ts
abstract class RawKeySignerError extends Error { abstract readonly code: string; readonly details?: object }

// authorization and binding
class InvalidPrivateKeyError            // INVALID_PRIVATE_KEY
class InvalidTransitionError            // INVALID_TRANSITION       (unparseable or indescribable)
class UnsupportedTransitionTypeError    // UNSUPPORTED_TRANSITION_TYPE (no authoritative requirement; fail closed)
class AuthorIdentityMismatchError       // AUTHOR_IDENTITY_MISMATCH
class KeyNotOnIdentityError             // KEY_NOT_ON_IDENTITY
class AmbiguousKeyError                 // AMBIGUOUS_KEY
class KeyPurposeMismatchError           // KEY_PURPOSE_MISMATCH     (actual, required, transitionType, action)
class KeySecurityLevelMismatchError     // KEY_SECURITY_LEVEL_MISMATCH
class KeyDisabledError                  // KEY_DISABLED
class StaleIdentityError                // STALE_IDENTITY           (freshness gate for high-risk offline ops)
// construction and state
class MissingStateError                 // MISSING_STATE            (offline build or nonce context missing)
class InvalidCoreFeeRateError           // INVALID_CORE_FEE_RATE
class InsufficientBalanceError          // INSUFFICIENT_BALANCE
class ClientRequiredError               // CLIENT_REQUIRED
// network and submission
class NonceConflictError                // NONCE_CONFLICT           (surfaced at broadcast; carries observed nonce and a retry affordance)
class BroadcastError                    // BROADCAST_ERROR          (retryable, transitionHash?, platformCode?)
class NetworkError                      // NETWORK_ERROR            (includes indeterminate delivery)
```

A supplied nonce that turns out to conflict is a submission-time (network) condition, not a
construction-time one, and its error reflects that. Transport failure is distinct from protocol
rejection, and a submission timeout is reported as indeterminate delivery.

## 7. The tooling adapter

One internal adapter holds all coupling to the `dash` SDK and the `@dashevo/wasm-dpp` layer, split into
protocol operations (parse and describe a transition, derive its requirement at the protocol's
granularity, construct, apply the nonce and signing-key id where the tooling requires it during
construction, serialize, sign, verify) and transport operations (reads, nonce source, broadcast). A
transport change does not touch authorization or signing. The public surface holds no tooling type, so a
tooling version bump is contained to the adapter and the `snapshotFromDashIdentity` helper. The
requirement derivation prefers a live protocol query where the tooling exposes the rule, and otherwise a
versioned internal map with conformance fixtures. Adapter conformance tests build fixed transitions
against the real tooling and assert the expected bytes and signatures, catching an upstream break at the
byte level without a live network. Where the protocol requires the nonce or signing-key id to be present
at construction (rather than set on an already-built transition), the adapter constructs with those
values rather than mutating serialized bytes.

## 8. Offline and broadcast-elsewhere

Authorization needs only the identity snapshot. Offline construction needs the surrounding state the
caller supplies (a `nonceContext`, the data-contract snapshot, the existing-document evidence for a
replace or delete, balance, fee rate). When a required piece is absent the library returns
`MissingStateError` rather than guessing. The snapshot carries capture metadata (for example a block
height). For a high-risk operation or the general path, if transport is present the library may
re-validate the key's disabled state against a fresh read, and for a stale snapshot on a
security-sensitive operation it raises `StaleIdentityError`. The signed result records the state basis it
relied on. `signTransition` on an already-constructed transition still validates the nonce (section 10),
it does not trust the embedded value. `broadcast` accepts a transition signed on another host, parses and
validates it, and when given a snapshot verifies the signing key and signature before submission. Because
the result carries bytes, a caller may also broadcast through the SDK directly.

## 9. Multi-party

The caller uses the signer, or a bound view, with whichever raw key satisfies the requirement for the
next transition. Different parties never share secrets. Sequencing across parties is the caller's, which
the protocol requires since each transition is single-signed and nonce-ordered, and the nonce seam
(section 10) makes that ownership explicit rather than only documented. The library does no cross-party
coordination.

## 10. Nonce handling

The nonce source is an injectable seam. The default implementation reads the current nonce through
transport (the identity nonce for identity-level transitions, the identity-and-contract nonce for
documents) and serializes allocation within the process, so two concurrent sign calls in one process
receive distinct successive nonces rather than racing for the same value. Every signing path, including
the general path, validates that the transition's nonce matches the expected next value for its scope
and that the scope matches the transition, or returns `MissingStateError` when neither transport nor an
explicit `nonceContext` is available. Offline construction requires an explicit `nonceContext`. A
cross-process or distributed conflict that only surfaces at submission is a `NonceConflictError`
carrying the observed nonce and a retry affordance. A lease or coordinator spanning processes can
replace the default source without changing any method signature, which is why the seam exists now even
though the default handles only in-process allocation.

## 11. Testing

The bulk of the suite is offline. Fixtures hold identities with keys of differing purpose, security
level, and disabled state, transitions authored by the right and the wrong identity, duplicate
public-key registrations, and known-good and known-bad private keys. The suite covers every
authorization and binding failure producing its exact typed error (wrong author, ambiguous key, wrong
purpose, wrong security level, disabled key, unsupported type, wrong nonce scope), disabled keys never
reaching the signing primitive, the general path refusing an indescribable transition, canonical
serialization round-trips, signatures verifying against the matched key, document create and replace and
delete evidence and nonce scoping, independent nonce sequences across contracts, fee-rate defaulting to
the floor and rejection of zero and out-of-sequence values, the balance preflight, `broadcast` rejecting
non-transition bytes, and the absence of fixture secrets in any observable output. Adapter conformance
tests run against the real tooling with mocked reads and transport. One manual devnet check runs the
full sequence documented in section 12.

## 12. Build plan, riskiest assumptions first

Two assumptions are the riskiest. First, that the tooling's lower building blocks can construct, carry
the signing-key id and nonce, sign with a raw key, serialize, and broadcast a transition the network
accepts with no HD wallet association. Second, that the adapter can parse a caller-supplied transition
and derive its exact requirement, author, signing-key id, and nonce scope, which every enforcement
invariant depends on. If the first fails, the answer is an upstream contribution. If the second fails,
the general path cannot be offered safely even if raw signing works.

1. Thin end-to-end slice. Build a document transition, an identity add-key transition, and an identity
   disable-key transition, and a withdrawal with fee-rate handling. Sign each with a raw key, verify
   offline, then broadcast to a local devnet and confirm acceptance. Also drive a caller-constructed
   transition through the general path. Add negative fixtures (wrong author, wrong signing-key id, wrong
   nonce scope, insufficient key security) and confirm the library refuses them before signing, while a
   live node would reject them if submitted. No further work begins until this passes.
2. Core: the authorization step with full binding, the internal signing primitive, the typed errors, the
   secret boundary with zeroing, and the requirement derivation, all offline-tested.
3. The adapter, split into protocol and transport operations, with conformance fixtures, and the
   injectable nonce source with its simple default.
4. The three hand-held flows with the discriminated document input, nonce validation, fee defaulting,
   and the balance preflight.
5. The general `signTransition` path and `broadcast` with input parsing and broadcast-elsewhere
   verification.
6. Offline construction with `nonceContext` and staleness handling, the optional bound view, and the
   multi-party pattern documented.
7. The manual devnet check, then release with semantic-versioning rules and a compatibility table.

## 13. Residual risks

1. The library depends on the shape of the tooling's lower building blocks, which can move. Adapter
   conformance tests plus a version-pinned live check catch a break, but an upgrade may still need real
   adapter work.
2. Offline state can be stale after capture. The library records the state basis, offers a freshness
   gate for high-risk operations, and fails on known inconsistencies, but it cannot detect a remote
   change without a fresh read.
3. Core fee-rate volatility between an offline withdrawal signing and its broadcast can cause rejection.
4. A malformed key or payload can trigger an uncatchable wasm panic in the tooling. The library
   validates inputs before crossing into wasm to reduce this, and the limit is documented.
5. Nonce conflicts under cross-process or distributed signing. The default source serializes allocation
   within one process, and the retry affordance plus the injectable seam handle the rest, but the
   default does not prevent two separate processes or hosts from racing for the same nonce. A
   distributed lease behind the seam is the mitigation for that deployment.

## 14. Exclusions

As stated in the requirements, each safe to exclude and each with a revisit trigger.

- X1. Protocol-gap workarounds a companion library cannot reach (immutable-document delete, document
  transfer or purchase). Reachable through the general path once the protocol and tooling ship them.
- X2. Threshold or multi-signature cryptography producing one signature from several shares. Blocked by
  the single-signature protocol. Revisit only on a ratified protocol transition that accepts such a
  signature.
- X3. A browser build and its bundling and in-browser key-handling concerns. Additive later if
  portability holds. Revisit on a concrete browser consumer with a key-storage threat model.
- X4. Hand-held convenience for the higher-risk identity updates beyond add-key (disable, rotate,
  master-level operations). Reachable now through the general path under the same invariants. Blessed as
  its own hand-held method once threat-modeled.

## Post-release deviations from this design (recorded 2026-07-14)

This section records where the shipped 0.1.0 deviates from the text above, so the design and the
implementation can be reconciled deliberately rather than drifting silently.

- Offline freshness (state basis, capture metadata, `StaleIdentityError`, the high-risk gate, sections 6
  and 8 above) did not ship. The v1 types existed with no implementation behind them and were removed
  before publish, on a release-review finding that unimplemented surface misleads consumers. The feature
  returns with its implementation as a semver-minor addition; TODO.md carries it as deferred.
- `AmbiguousKeyError` was removed. The deterministic lowest-key-id tie-break makes ambiguity unreachable.
- The general path shipped without a `nonceContext` parameter and without declared-signing-key extraction
  from the parsed transition (the API sketch in section 3 shows `nonceContext?` on `signTransition`).
  Nonce and revision correctness on the general path rest with the caller, as the README states. DECIDED
  (2026-07-14): the design is amended, the embedded nonce is authoritative on the general path, and the
  network's own ordering enforcement is the backstop. The sketched binding returns only if a real
  general-path consumer needs it, together with the negative-case tests the holistic review outlined.
- `broadcast` validates parseability, not signed validity, and takes no identity snapshot for signature
  verification. The README describes the shipped behavior accurately.
- The signer's configured network became an enforcement boundary post-review: every key-bearing operation
  refuses an identity snapshot whose network differs from the signer's.
- F10's claim that the core avoids Node-only patterns did not hold: `createRequire`, `Buffer`, and
  `node:crypto` are load-bearing in the adapter, the secret boundary, and the flows. Node.js is the real
  v1 target, and a browser build (X3) would need those seams reworked, not just bundled. The holistic
  review also misread D2's "retry affordance" as automatic retry; the affordance is `NonceConflictError`
  carrying the observed nonce, which shipped as designed.
