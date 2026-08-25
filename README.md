# arbor-registry

`arbor-registry` is a standalone component with a pure Nix library and an
optional runtime package. The library validates canonical signed-record
envelopes, reconciles accepted history, retains unknown or invalid transport
records in quarantine, materializes consumer projections, and validates/
queries relationship graphs. The runtime package adds local signed event
storage, identity generations, and a SQLite materialized view for node
processes.

The pipeline is intentionally explicit:

```text
raw transport -> envelope validation -> accepted history -> materialized state
```

`makeTransport` is a deterministic in-process fixture for tests and snapshots.
It is only an append/fetch fixture. The runtime adapter uses Ed25519 signatures
and an append-only local provider. `OrbitDBProvider` is an optional,
runtime-only Unix-socket adapter for the reference registry daemon's bounded
`append`/`list` contract; it does not import OrbitDB or Helia, and Nix
evaluation never opens the socket. Event translation belongs in its explicit
`encode`/`decode` hooks; validation, enrollment authority, receipts, and
reconciliation remain outside the transport seam.

Record families are enumerated by `familyNames`. Relationships support active,
suspended, severed, and standby states; standby edges are retained but are not
included in active parent traversal. Multiple parents are valid. Parent cycles
are reported by `validateGraph`; peer relationships are not parent cycles.

The runtime Provider seam is intentionally raw and transport-only:

```text
append(record) -> durable zero-based cursor
fetch(cursor, limit) -> ordered (cursor, record) page
```

An implementation must preserve exact-record replay idempotence, keep cursors
monotonic, and bound each page. It must not validate authority or materialize
state; `Runtime` performs signature, compatibility, lineage, quarantine, and
reconciliation checks after transport ingestion. `FileProvider` remains the
local integer-cursor contract; `OrbitDBProvider` exposes the daemon's opaque
hash/`v1:<sequence>` cursors through the same runtime-only seam. It is not
required by Nix evaluation.

The library is exposed as both `registry` and `lib` from the flake. Run:

```sh
nix flake check ./packages/arbor-registry
nix fmt ./packages/arbor-registry
```

The runtime checks and package can be exercised with `nix flake check` and
`nix build .#arbor-registry-runtime`. Runtime identity keys and accepted state
are created under explicit runtime paths; they are never inputs to Nix
evaluation and must not be committed.
