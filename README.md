# arbor-registry

`arbor-registry` is a standalone, pure Nix library for the data boundary of
Arbor Registry. It validates canonical signed-record envelopes, reconciles
accepted history, retains unknown or invalid transport records in quarantine,
materializes consumer projections, and validates/queries relationship graphs.

The pipeline is intentionally explicit:

```text
raw transport -> envelope validation -> accepted history -> materialized state
```

`makeTransport` is a deterministic in-process fixture for tests and snapshots.
It is only an append/fetch fixture; this package does not implement OrbitDB,
Helia, OpenBao, cryptography, identity storage, or secret delivery. Inject a
signer implementing `sign` and `verify` for tests or a runtime adapter.

Record families are enumerated by `familyNames`. Relationships support active,
suspended, severed, and standby states; standby edges are retained but are not
included in active parent traversal. Multiple parents are valid. Parent cycles
are reported by `validateGraph`; peer relationships are not parent cycles.

The library is exposed as both `registry` and `lib` from the flake. Run:

```sh
nix flake check ./packages/arbor-registry
nix fmt ./packages/arbor-registry
```
