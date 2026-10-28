# arbor-registry

The Registry flake pins nixpkgs to an immutable revision containing OpenBao
2.7.2 for its runtime and VM checks. This is dependency evidence, not evidence
that any host has been deployed or that a particular OpenBao feature is in use.

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

Reconciliation consumes the complete retained record set. Its conflict,
revocation, lineage, authority, graph, capability, quarantine, and projection
outputs are canonicalized independently of transport arrival order. The
runtime invokes this bounded reconciliation pass after each ingestion batch;
providers remain append/fetch-only and do not perform authorization.

`makeTransport` is a deterministic in-process fixture for tests and snapshots.
It is only an append/fetch fixture. The runtime adapter uses Ed25519 signatures
and an append-only local provider. `OrbitDBProvider` is an optional,
runtime-only Unix-socket adapter for `arbor-registryd`'s bounded `append`/`list`
contract; it does not import OrbitDB or Helia, and Nix evaluation never opens
the socket. The optional Node package in `transport/` contains only generic
OrbitDB/Helia event-log storage and this socket protocol. It omits the
reference daemon's clusterctl/OpenBao, content, manifest, ACL, and event
admission controllers. Event translation belongs in its explicit `encode`/
`decode` hooks; validation, enrollment authority, receipts, and
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
opaque cursors through the same runtime-only seam. It is not required by Nix
evaluation.

Transport pages now emit `v3-after:<position>` continuations and opaque
`v3:<position>` record sequences. Positions are local to the persisted stream
index, ordered by first observation of an exact event, and retained when a
different OrbitDB hash wins duplicate reconciliation. Keep the transport index
with its consumer state; cursors are not portable between nodes or rebuilt
indexes. Append cursors remain inclusive `v2:<hash>` cursors.

On upgrade, `v1:<offset>`, `v2-after:<hash>`, and legacy raw-hash resume cursors
conservatively replay all retained events in bounded pages. Their old ordering
cannot establish a consumed prefix, even when the anchor still exists. A missing
old append anchor also replays from the beginning. Consumers must use each
returned `nextCursor`; Registry atomically commits it with idempotent ingestion,
so interrupted replay resumes safely and repeats do not duplicate accepted or
quarantined history. No authority checks are bypassed. An empty/unavailable page
does not advance progress.

Already skipped records are recovered only as retained history is fetched and
validated; upgrading alone is not proof of recovery. Allow catch-up to finish
and compare expected accepted/quarantined records before relying on an affected
runtime. Records absent from retained transport require separate recovery.
Downgrading after saving v3 cursors is unsupported; preserve state and restore a
compatible daemon rather than deleting cursors or the index.

The library is exposed as both `registry` and `lib` from the flake. Run:

```sh
nix flake check ./packages/arbor-registry
nix fmt ./packages/arbor-registry
```

The runtime checks and package can be exercised with `nix flake check` and
`nix build .#arbor-registry-runtime`; the optional daemon is
`.#arbor-registry-transport`. It requires Node 22 and its pinned npm closure,
and is not needed by the Python runtime or pure Nix checks. Runtime identity keys and accepted state
are created under explicit runtime paths; they are never inputs to Nix
evaluation and must not be committed. `generate_keypair` refuses to replace
existing active key files; use a numbered `generation` to retain prior keys,
or explicitly request `rotation=True` for an active-key rotation.

For a deliberately bootstrapped standalone node, construct `Runtime` with its
runtime-held `node_key` and call `local_genesis(identity, domain)` exactly once.
This emits the existing generation-one `node-identity` record, self-authorized
only for that exact identity and domain. The runtime persists only the public
key, domain, and record digest; repeated identical calls are idempotent and a
different identity, domain, key, or state is rejected. The ordinary
`make_enrollment_request` flow remains self-signed proof for external
authority approval and does not create authority by itself.

## OpenBao runtime provider

`nixosModules.vault-runtime` starts one `arbor-vault-runtime-<binding>` service
per credential binding. It invokes the runtime-only `arbor-openbao-provider`,
writes credentials with same-directory atomic rename and mode `0600`, and
writes only a SHA-256 readiness marker under `/run/arbor-vaultd/ready`.
It polls for rotation and runs `systemctl try-restart <consumer>` after a
changed value is durably written. Failed refreshes retain the last good value;
an initial failure leaves the consumer blocked because its fetcher is not
ready.

The module requires either `runtimePackage` (normally the
`arbor-registry-runtime` package from the same input) or an explicit
runtime-only `runtimeCommand`. HTTP providers require `authMethod =
"external"` and a `tokenFile` under `/run` or `/var/lib/arbor`; AppRole,
Kubernetes, and Unix authentication are handled only by an injected provider
command, which receives the declared method in its JSON request.

Set `providers.<name>.command` to an injected command reading
`{"path": ..., "field": ...}` on stdin and returning an OpenBao-shaped JSON
response. Alternatively set `address` and an optional runtime `tokenFile`;
the HTTP adapter performs `GET /v1/<path>` with the runtime token and optional
namespace. Token contents are never Nix option values, command-line arguments,
or store inputs. The executable does not start OpenBao in production: live
integration uses an externally managed endpoint or injected adapter command.
The package check also starts an isolated OpenBao dev server and verifies HTTP
delivery, permissions, readiness, and a second rotation read. Set
`useUpstreamVaultd = true` and `useProviderBridge = true` to group provider
files into the pinned upstream `/run/systemd-vaultd/secrets/<service>.service.json`
contract; `vault-provider-bridge-vm` proves the initial OpenBao → provider →
bridge → vaultd socket path with multiple credentials. Bridge rotation keeps
the provider watcher and retries consumer refresh after failures, but the VM
does not yet exercise a long-lived rotation/restart failure. Production auth
remains external.

## OrbitDB transport realm

For independent daemons to join one registry, each daemon receives the same
public `ARBOR_REGISTRY_REALM_ID` and `ARBOR_REGISTRY_PROTOCOL_EPOCH` (the latter
defaults to `1`). The realm ID is a per-registry bootstrap discriminator, not a
node identity or authority role. In realm mode the daemon derives a stable
stream name and uses a deterministic raw-write access controller, so peers with
different identities open the same OrbitDB address. The resolved realm, epoch,
database addresses, listen addresses, and connected peer IDs are available from
the authenticated `status` socket operation.

The daemon persists `{ realmId, protocolEpoch, databaseAddresses }` in
`transport-bootstrap.json` below its state directory and refuses a conflicting
configured realm. OrbitDB raw writes are intentionally not Arbor authorization:
records remain subject to Arbor signature, compatibility, issuer, and
relationship validation before they enter accepted or materialized state.

Recovery authorization is deliberately stricter than ordinary envelope
validation. Every approval must identify a trusted approver, role, and
approver-key generation, and all approvals must target the lost generation
and recovery operation. Pure Nix does not implement cryptography: callers
must provide a `signatureVerifier` function backed by a real verifier. If it
is absent, recovery is rejected; a non-empty signature field alone is never
authorization. The runtime's Ed25519 verifier is the reference boundary for
that interface.
