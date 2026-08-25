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
and an append-only local provider, but deliberately does not bundle OrbitDB,
Helia, OpenBao, or a central manager. Network transports and secret delivery
remain external integrations.

Record families are enumerated by `familyNames`. Relationships support active,
suspended, severed, and standby states; standby edges are retained but are not
included in active parent traversal. Multiple parents are valid. Parent cycles
are reported by `validateGraph`; peer relationships are not parent cycles.

The library is exposed as both `registry` and `lib` from the flake. Run:

```sh
nix flake check ./packages/arbor-registry
nix fmt ./packages/arbor-registry
```

The runtime checks and package can be exercised with `nix flake check` and
`nix build .#arbor-registry-runtime`. Runtime identity keys and accepted state
are created under explicit runtime paths; they are never inputs to Nix
evaluation and must not be committed.
