# Security policy

dash-rawkey-signer handles raw private keys for signing Dash Platform state transitions. Its security
model and honest limits are documented in the README. This file covers reporting and maintenance.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories on this repository
(Security tab, "Report a vulnerability"). Please do not open a public issue for anything that could
expose key material or let a malformed input be signed. Reports get an acknowledgment within a week.

## Supported versions

The latest published 0.x release receives fixes. Older releases are not patched; upgrade to the newest
release to receive security fixes. Breaking changes before 1.0.0 can land in minor releases and are
called out in the CHANGELOG.

## Maintenance commitments

- The protocol tooling (`@dashevo/wasm-dpp`) is pinned exactly, and upgrading it is never a routine
  bump. Each upgrade re-validates the WebAssembly bridge before release.
- Dependency advisories for the pinned tooling and `@dashevo/dashcore-lib` are reviewed before each
  release, and a corrective release follows any advisory that affects signing or key handling.
- Node.js support follows the engines field (currently 20 or later).
