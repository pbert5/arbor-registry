import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nacl.signing import SigningKey

from arbor_registry_runtime import FileProvider, OrbitDBProvider, Provider, Runtime, RuntimeKey, canonical_json, generate_keypair
from arbor_registry_runtime.runtime import (
    approve_enrollment,
    make_identity_generation,
    make_lifecycle_record,
    make_recovery_approval,
    make_recovery_authorization,
    make_revocation,
    make_receipt,
    make_enrollment_request,
    make_local_genesis,
)
from arbor_registry_runtime.runtime import _key
from arbor_registry_runtime.openbao_provider import _json_value


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        key = RuntimeKey("root", SigningKey.generate())
        self.runtime = Runtime(root / "state", FileProvider(root / "raw" / "history.jsonl"), {"root": key.public_key})
        self.key = key

    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()

    def envelope(self, record_id, generation=1, predecessor=None, schema="node-identity", payload=None, record_version=1):
        record = {"protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1, "recordVersion": record_version,
                  "recordId": record_id, "generation": generation, "predecessor": predecessor,
                  "issuer": "root", "schema": schema, "payload": payload or {"id": record_id}}
        record["signature"] = self.key.sign({k: v for k, v in record.items() if k != "signature"})
        return record

    def test_partition_reorder_and_materialization(self):
        parent = self.envelope("node", payload={"id": "node", "aliases": ["old"]})
        child = self.envelope("node", 2, "node", payload={"id": "node", "aliases": ["new"]}, record_version=2)
        self.assertEqual(self.runtime.ingest([child])[0]["status"], "quarantined")
        self.assertEqual(self.runtime.projection(), {})
        self.runtime.ingest([parent])
        self.assertEqual(self.runtime.projection()["node"]["payload"]["aliases"], ["new"])

    def test_replay_is_idempotent_and_raw_history_is_append_only(self):
        record = self.envelope("one")
        self.runtime.ingest([record, record])
        self.assertEqual(len(self.runtime.accepted()), 1)
        raw = Path(self.temp.name) / "raw" / "history.jsonl"
        self.assertEqual(len(raw.read_text().splitlines()), 1)

    def test_invalid_signature_and_unknown_record_are_quarantined(self):
        invalid = self.envelope("bad")
        invalid["payload"]["id"] = "tampered"
        unknown = self.envelope("future", schema="future-record")
        self.runtime.ingest([invalid, unknown])
        reasons = {item["reason"] for item in self.runtime.quarantine()}
        self.assertEqual(reasons, {"invalid-signature", "unknown-schema"})

    def test_bounded_cursors(self):
        self.runtime.ingest([self.envelope("one"), self.envelope("two")])
        self.assertEqual([r["recordId"] for r in self.runtime.accepted(1, 1)], ["two"])
        with self.assertRaises(ValueError):
            self.runtime.accepted(0, 1001)

    def test_provider_contract_is_durable_idempotent_and_cursor_bounded(self):
        provider = self.runtime.provider
        self.assertIsInstance(provider, Provider)
        first = self.envelope("one")
        second = self.envelope("two")
        self.assertEqual(provider.append(first), 0)
        self.assertEqual(provider.append(first), 0)
        self.assertEqual(provider.append(second), 1)
        self.assertEqual(provider.fetch(0, 1), [(0, first)])
        self.assertEqual(provider.fetch(1, 1000), [(1, second)])
        with self.assertRaises(ValueError):
            provider.fetch(0, 1001)

    def test_public_state_has_no_private_key_material(self):
        self.runtime.ingest([self.envelope("one")])
        files = list(Path(self.temp.name, "state").rglob("*"))
        self.assertFalse(any(path.name.endswith(".private") for path in files))
        self.assertNotIn(bytes(self.key.signing_key).hex(), json.dumps(self.runtime.projection()))
        self.assertTrue(canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}')

    def test_generate_keypair_refuses_implicit_overwrite_and_supports_explicit_rotation(self):
        key_dir = Path(self.temp.name) / "identity"
        first = generate_keypair(key_dir, "operator")
        with self.assertRaises(FileExistsError):
            generate_keypair(key_dir, "operator")
        rotated = generate_keypair(key_dir, "operator", rotation=True)
        self.assertNotEqual(first.public_key, rotated.public_key)

    def test_generate_keypair_preserves_prior_generations(self):
        key_dir = Path(self.temp.name) / "identity"
        first = generate_keypair(key_dir, "operator", generation=1)
        second = generate_keypair(key_dir, "operator", generation=2)
        self.assertNotEqual(first.public_key, second.public_key)
        self.assertTrue((key_dir / "operator.g1.private").exists())
        self.assertTrue((key_dir / "operator.g2.private").exists())

    def test_generate_keypair_rejects_path_traversal_and_absolute_issuers(self):
        key_dir = Path(self.temp.name) / "identity"
        for issuer in ("../escape", "nested/operator", "\\absolute", "/absolute", ".", ".."):
            with self.assertRaises(ValueError):
                generate_keypair(key_dir, issuer)

    def test_generate_keypair_validates_permissions_before_writing(self):
        key_dir = Path(self.temp.name) / "permissioned-identity"
        key_dir.mkdir(mode=0o700)
        key_dir.chmod(0o755)
        with self.assertRaises(ValueError):
            generate_keypair(key_dir, "operator")
        self.assertEqual(list(key_dir.iterdir()), [])

        key_dir.chmod(0o700)
        private = key_dir / "operator.private"
        private.write_text("old", encoding="ascii")
        private.chmod(0o644)
        with self.assertRaises(ValueError):
            generate_keypair(key_dir, "operator", rotation=True)
        self.assertEqual(private.read_text(encoding="ascii"), "old")

    def test_orbitdb_provider_maps_bounded_socket_contract(self):
        import socketserver
        import threading

        seen = {}

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                seen.update(json.loads(self.rfile.readline()))
                self.wfile.write(json.dumps({"ok": True, "records": [{"hash": "h1", "sequence": 7, "event": {"id": 1}}], "nextCursor": "v1:8"}).encode() + b"\n")

        path = Path(self.temp.name) / "registry.sock"
        server = socketserver.UnixStreamServer(str(path), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            provider = OrbitDBProvider(path, "membership", token="secret")
            self.assertEqual(provider.fetch(0, 1), [(7, {"id": 1})])
            self.assertEqual(seen["cursor"], "v1:0")
            self.assertEqual(seen["token"], "secret")
            self.assertEqual(provider.next_cursor, "v1:8")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_orbitdb_provider_requires_append_cursor(self):
        import socketserver
        import threading

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(json.dumps({"ok": True, "hash": "h1"}).encode() + b"\n")

        path = Path(self.temp.name) / "append.sock"
        server = socketserver.UnixStreamServer(str(path), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with self.assertRaises(ValueError):
                OrbitDBProvider(path, "membership").append({"id": 1})
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_orbitdb_provider_rejects_reordered_sequences(self):
        import socketserver
        import threading

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(json.dumps({
                    "ok": True,
                    "records": [
                        {"hash": "h1", "sequence": 2, "event": {"id": 1}},
                        {"hash": "h2", "sequence": 2, "event": {"id": 2}},
                    ],
                    "nextCursor": "v1:3",
                }).encode() + b"\n")

        path = Path(self.temp.name) / "ordered.sock"
        server = socketserver.UnixStreamServer(str(path), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with self.assertRaises(ValueError):
                OrbitDBProvider(path, "membership").fetch(0, 2)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_envelope_compatibility_and_unsafe_values_are_quarantined(self):
        cases = {
            "unknown-epoch": {"protocolEpoch": 2},
            "unsupported-wire-version": {"wireVersion": 2},
            "unsupported-schema-version": {"schemaVersion": 2},
            "unsupported-required-feature": {"requiredFeatures": ["future"]},
            "unsafe-value": {"payload": {"path": "/run/secrets/token"}},
        }
        records = []
        for changes in cases.values():
            record = self.envelope(changes.get("recordId", "compat" + str(len(records))), payload={"id": "x"})
            record.update(changes)
            record["signature"] = self.key.sign({k: v for k, v in record.items() if k != "signature"})
            records.append(record)
        outcomes = self.runtime.ingest(records)
        self.assertEqual([outcome["reason"] for outcome in outcomes], list(cases))
        self.assertEqual(self.runtime.accepted(), [])

    def test_endpoint_credentials_embedded_in_urls_are_quarantined(self):
        record = self.envelope(
            "endpoint-url",
            schema="endpoint",
            payload={"address": "https://user:password@example.invalid/api"},
        )
        outcome = self.runtime.ingest([record])[0]
        self.assertEqual(outcome["status"], "quarantined")
        self.assertEqual(outcome["reason"], "unsafe-value")

    def test_bearer_values_are_quarantined_even_without_secret_field_names(self):
        record = self.envelope(
            "endpoint-bearer",
            schema="endpoint",
            payload={"authorization": "Bearer runtime-secret"},
        )
        outcome = self.runtime.ingest([record])[0]
        self.assertEqual(outcome["status"], "quarantined")
        self.assertEqual(outcome["reason"], "unsafe-value")

    def test_conflicting_record_key_quarantines_both_variants(self):
        first = self.envelope("same")
        second = self.envelope("same", payload={"id": "different"})
        outcomes = self.runtime.ingest([first, second])
        self.assertEqual([outcome["reason"] for outcome in outcomes], ["conflicting-record-key", "conflicting-record-key"])
        self.assertEqual(self.runtime.accepted(), [])
        self.assertEqual({item["reason"] for item in self.runtime.quarantine()}, {"conflicting-record-key"})

    def test_forks_and_rollbacks_never_enter_accepted_state(self):
        parent = self.envelope("parent")
        fork_a = self.envelope("a", 2, "parent")
        fork_b = self.envelope("b", 2, "parent")
        self.runtime.ingest([parent, fork_a, fork_b])
        self.assertEqual(self.runtime.accepted(), [parent])
        self.assertEqual({item["reason"] for item in self.runtime.quarantine()}, {"forked-lineage"})
        newer = self.envelope("rollback", 2, "rollback", record_version=2)
        old = self.envelope("rollback", 1)
        # The generation-two record is invalid until its predecessor exists;
        # once both arrive, the stale generation-one record is not accepted.
        self.runtime.ingest([newer, old])
        accepted_keys = {_key(record) for record in self.runtime.accepted()}
        self.assertIn("rollback:2", accepted_keys)
        self.assertNotIn("rollback:1", accepted_keys)
        self.assertIn("anti-rollback", {item["reason"] for item in self.runtime.quarantine()})

    def test_enrollment_is_authority_approved_and_lifecycle_families_are_accepted(self):
        node_key = RuntimeKey("node", SigningKey.generate())
        request = make_enrollment_request(node_key, "node", platform="linux", nonce="abcdefghijklmnop")
        identity = approve_enrollment(request, self.key)
        self.assertEqual(self.runtime.ingest([identity])[0]["status"], "accepted")
        records = [
            make_lifecycle_record(self.key, "enrollment", "enrollment:node", {
                "identity": "node", "publicKey": node_key.public_key,
                "requestDigest": "request", "approvedBy": "root",
            }),
            make_revocation(self.key, "other", 1, "retired"),
            make_receipt(self.key, "node", "digest"),
        ]
        self.assertEqual([item["status"] for item in self.runtime.ingest(records)], ["accepted"] * 3)

    def test_local_genesis_is_explicit_scoped_and_idempotent_across_restart(self):
        node = RuntimeKey("node", SigningKey.generate())
        state = Path(self.temp.name) / "genesis-state"
        raw = FileProvider(Path(self.temp.name) / "genesis-raw" / "history.jsonl")
        runtime = Runtime(state, raw, {"root": self.key.public_key}, node_key=node)
        try:
            outcome = runtime.local_genesis("node", "example.internal", platform="linux")
            self.assertEqual(outcome["status"], "accepted")
            self.assertEqual(runtime.projection()["node"]["payload"]["domain"], "example.internal")
            self.assertNotIn(bytes(node.signing_key).hex(), json.dumps(runtime.projection()))
            self.assertEqual(runtime.local_genesis("node", "example.internal", platform="linux"), outcome)
            with self.assertRaises(ValueError):
                runtime.local_genesis("node", "other.internal", platform="linux")
            with self.assertRaises(ValueError):
                runtime.local_genesis("other", "example.internal", platform="linux")
        finally:
            runtime.close()
        restarted = Runtime(state, raw, {"root": self.key.public_key}, node_key=node)
        try:
            self.assertEqual(restarted.projection()["node"]["generation"], 1)
            self.assertEqual(restarted.local_genesis("node", "example.internal", platform="linux")["status"], "accepted")
        finally:
            restarted.close()

    def test_local_authority_cannot_escape_its_identity_and_domain(self):
        node = RuntimeKey("node", SigningKey.generate())
        runtime = Runtime(Path(self.temp.name) / "scoped-state", FileProvider(Path(self.temp.name) / "scoped-raw" / "history.jsonl"), {}, node_key=node)
        try:
            runtime.local_genesis("node", "example.internal")
            escaped = make_local_genesis(node, "node", "example.internal")
            escaped["payload"]["identity"] = "foreign"
            escaped["signature"] = node.sign({key: value for key, value in escaped.items() if key != "signature"})
            self.assertEqual(runtime.ingest([escaped])[0]["reason"], "unauthorized-local-authority-scope")
        finally:
            runtime.close()

    def test_local_genesis_rejects_signed_variants_and_unrelated_self_roots(self):
        node = RuntimeKey("node", SigningKey.generate())
        foreign = RuntimeKey("foreign", SigningKey.generate())
        runtime = Runtime(Path(self.temp.name) / "genesis-variants", FileProvider(Path(self.temp.name) / "genesis-variants-raw" / "history.jsonl"), {}, node_key=node)
        try:
            runtime.local_genesis("node", "example.internal")
            variant = make_local_genesis(node, "node", "example.internal", platform="other")
            self.assertEqual(runtime.ingest([variant])[0]["reason"], "conflicting-record-key")
            unrelated = make_local_genesis(foreign, "foreign", "example.internal")
            runtime.public_keys["foreign"] = foreign.public_key
            self.assertEqual(runtime.ingest([unrelated])[0]["reason"], "unauthorized-authority")
        finally:
            runtime.close()

    def test_lineage_invalid_relationship_cannot_authorize_identity_or_capability(self):
        child = RuntimeKey("child", SigningKey.generate())

        def signed(key, record_id, issuer, schema, payload, predecessor=None):
            record = {"protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
                      "recordVersion": 1, "recordId": record_id, "generation": 2 if predecessor else 1,
                      "predecessor": predecessor, "issuer": issuer, "schema": schema, "payload": payload}
            record["signature"] = key.sign(record)
            return record

        self.runtime.public_keys["child"] = child.public_key
        forged_edge = signed(self.key, "forged-edge", "root", "relationship", {
            "relationshipId": "forged-edge", "from": "root", "to": "child",
            "kind": "parent", "status": "active", "authorityRoot": "root",
        }, predecessor="missing")
        identity = signed(child, "child", "child", "node-identity", {"id": "child", "authorityRoot": "root"})
        self.assertEqual(self.runtime.ingest([forged_edge, identity])[-1]["reason"], "unauthorized-authority")

    def test_capability_delegation_requires_active_issuer_subject_edge(self):
        child = RuntimeKey("child", SigningKey.generate())
        self.runtime.public_keys["child"] = child.public_key

        def signed(key, record_id, issuer, payload):
            record = {"protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
                      "recordVersion": 1, "recordId": record_id, "generation": 1,
                      "predecessor": None, "issuer": issuer, "schema": "capability", "payload": payload}
            record["signature"] = key.sign(record)
            return record

        grant = signed(child, "grant", "child", {"subject": "grandchild", "authorityRoot": "root", "capabilities": ["observe"]})
        self.assertEqual(self.runtime.ingest([grant])[0]["reason"], "unauthorized-capability")

    def test_authority_is_graph_derived_and_roots_compose(self):
        child = RuntimeKey("child", SigningKey.generate())
        foreign = RuntimeKey("foreign", SigningKey.generate())

        def signed(key, record_id, issuer, schema, payload):
            record = {
                "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
                "recordVersion": 1, "recordId": record_id, "generation": 1,
                "predecessor": None, "issuer": issuer, "schema": schema,
                "payload": payload,
            }
            record["signature"] = key.sign(record)
            return record

        parent_edge = signed(self.key, "root-child", "root", "relationship", {
            "relationshipId": "root-child", "from": "root", "to": "child",
            "kind": "parent", "status": "active", "authorityRoot": "root",
        })
        child_identity = signed(child, "child", "child", "node-identity", {
            "id": "child", "authorityRoot": "root",
        })
        unrelated = signed(foreign, "foreign", "foreign", "node-identity", {
            "id": "foreign", "authorityRoot": "root",
        })
        self.runtime.public_keys.update({"child": child.public_key, "foreign": foreign.public_key})
        outcomes = self.runtime.ingest([child_identity, unrelated, parent_edge])
        self.assertEqual(outcomes[0]["status"], "accepted")
        self.assertEqual(outcomes[1]["reason"], "unauthorized-authority")
        self.assertIn("child", self.runtime.projection())

        root_grant = signed(self.key, "grant-child", "root", "capability", {
            "subject": "child", "authorityRoot": "root", "capabilities": ["observe"],
        })
        child_edge = signed(child, "child-grandchild", "child", "relationship", {
            "relationshipId": "child-grandchild", "from": "child", "to": "grandchild",
            "kind": "parent", "status": "active", "authorityRoot": "root",
        })
        amplification = signed(child, "grant-grandchild", "child", "capability", {
            "subject": "grandchild", "authorityRoot": "root", "capabilities": ["admin"],
        })
        self.assertEqual(self.runtime.ingest([root_grant, child_edge, amplification])[-1]["reason"],
                         "unauthorized-capability")

        root_b = RuntimeKey("root-b", SigningKey.generate())
        runtime = Runtime(
            Path(self.temp.name) / "composed-state",
            FileProvider(Path(self.temp.name) / "composed-raw" / "history.jsonl"),
            {"root": self.key.public_key, "root-b": root_b.public_key},
            authority_issuers={"root", "root-b"},
        )
        try:
            root_b_record = signed(root_b, "root-b", "root-b", "node-identity", {"id": "root-b"})
            self.assertEqual(runtime.ingest([self.envelope("root-a"), root_b_record])[1]["status"], "accepted")
        finally:
            runtime.close()

    def test_graph_cycles_are_rejected_after_delegation_resolution(self):
        a = RuntimeKey("a", SigningKey.generate())
        b = RuntimeKey("b", SigningKey.generate())

        def edge(key, record_id, issuer, source, target):
            record = {
                "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
                "recordVersion": 1, "recordId": record_id, "generation": 1,
                "predecessor": None, "issuer": issuer, "schema": "relationship",
                "payload": {"relationshipId": record_id, "from": source, "to": target,
                            "kind": "parent", "status": "active", "authorityRoot": "root"},
            }
            record["signature"] = key.sign(record)
            return record

        self.runtime.public_keys.update({"a": a.public_key, "b": b.public_key})
        records = [
            edge(self.key, "root-a", "root", "root", "a"),
            edge(a, "a-b", "a", "a", "b"),
            edge(b, "b-a", "b", "b", "a"),
        ]
        self.runtime.ingest(records)
        self.assertEqual([record["recordId"] for record in self.runtime.accepted()], ["root-a"])
        self.assertEqual({item["reason"] for item in self.runtime.quarantine()}, {"parent-cycle"})

    def test_cycles_are_scoped_to_authority_root(self):
        def edge(record_id, source, target, root):
            record = {
                "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
                "recordVersion": 1, "recordId": record_id, "generation": 1,
                "predecessor": None, "issuer": "root", "schema": "relationship",
                "payload": {"relationshipId": record_id, "from": source, "to": target,
                            "kind": "parent", "status": "active", "authorityRoot": root},
            }
            record["signature"] = self.key.sign(record)
            return record

        records = [edge("a", "one", "two", "root-a"), edge("b", "two", "one", "root-b")]
        self.assertEqual(Runtime._cycle_indexes(records), set())

    def test_severed_parent_edge_preserves_established_child_identity(self):
        child = RuntimeKey("child", SigningKey.generate())
        self.runtime.public_keys["child"] = child.public_key
        edge = {
            "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
            "recordVersion": 1, "recordId": "severed-edge", "generation": 1,
            "predecessor": None, "issuer": "root", "schema": "relationship",
            "payload": {"relationshipId": "severed-edge", "from": "root", "to": "child",
                        "kind": "parent", "status": "severed", "authorityRoot": "root"},
        }
        edge["signature"] = self.key.sign(edge)
        identity = {
            "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
            "recordVersion": 1, "recordId": "child", "generation": 1,
            "predecessor": None, "issuer": "child", "schema": "node-identity",
            "payload": {"identity": "child", "publicKey": child.public_key, "authorityRoot": "root"},
        }
        identity["signature"] = child.sign(identity)
        self.assertEqual([item["status"] for item in self.runtime.ingest([identity, edge])], ["accepted", "accepted"])
        self.assertIn("child", self.runtime.projection())

    def test_active_generation_and_revocation_gate_validation_and_projection(self):
        generation_one = make_identity_generation(self.key, "node", 1, "old-key")
        generation_two = make_identity_generation(
            self.key, "other", 2, "new-key", predecessor="other:1",
            recovery_authorization={"authorization": "approved"},
        )
        generation_two["payload"]["recoveryAuthorizationDigest"] = "not-the-digest"
        generation_two["signature"] = self.key.sign({key: value for key, value in generation_two.items() if key != "signature"})
        self.assertEqual(self.runtime.ingest([generation_one])[0]["status"], "accepted")
        self.assertEqual(self.runtime.ingest([generation_two])[0]["reason"], "missing-recovery-authorization")

        authorization = make_recovery_authorization(
            self.key, "node", 1, "new-key",
            [make_recovery_approval(self.key, "node", 1, role="operator", approver_generation=1)],
        )
        generation_two = make_identity_generation(
            self.key, "node", 2, "new-key", predecessor="node:1", recovery_authorization=authorization,
        )
        self.assertEqual(self.runtime.ingest([authorization, generation_two])[1]["status"], "accepted")
        event = self.envelope("event", payload={"identity": "node", "identityGeneration": 1})
        self.assertEqual(self.runtime.ingest([event])[0]["reason"], "stale-generation")
        revoked = make_revocation(self.key, "node", 2, "compromised")
        self.runtime.ingest([revoked])
        self.assertNotIn("node:2", {record["recordId"] for record in self.runtime.accepted()})

    def test_recovery_generation_replays_out_of_order_and_rejects_stale_approver(self):
        operator = RuntimeKey("operator", SigningKey.generate())
        replacement = RuntimeKey("node-replacement", SigningKey.generate())
        runtime = Runtime(
            Path(self.temp.name) / "recovery-state",
            FileProvider(Path(self.temp.name) / "recovery-raw" / "history.jsonl"),
            {"root": self.key.public_key, "operator": operator.public_key},
            approver_roles={"operator": {"operator"}, "parent": set(), "peer": set()},
        )
        try:
            operator_generation = make_identity_generation(self.key, "operator", 1, operator.public_key)
            lost = make_identity_generation(self.key, "node", 1, "old-key")
            revoked = make_revocation(self.key, "node", 1, "lost-key")
            approval = make_recovery_approval(operator, "node", 1, role="operator", approver_generation=1)
            authorization = make_recovery_authorization(self.key, "node", 1, replacement.public_key, [approval])
            recovered = make_identity_generation(
                self.key, "node", 2, replacement.public_key,
                predecessor="node:1", recovery_authorization=authorization,
            )

            outcomes = runtime.ingest([recovered, authorization, lost, operator_generation, revoked])
            self.assertEqual({item["status"] for item in outcomes}, {"accepted", "quarantined"})
            self.assertEqual(runtime.projection()["node"]["generation"], 2)
            self.assertEqual(
                {(record["recordId"], record["generation"]) for record in runtime.accepted()},
                {
                    ("node", 2), ("operator", 1),
                    ("node:recovery:1", 1), ("node:revocation:1", 1),
                },
            )

            current_operator = make_identity_generation(self.key, "operator", 2, "new-operator-key")
            runtime.ingest([current_operator])
            self.assertIn(
                "stale-approver-generation",
                {item["reason"] for item in runtime.quarantine()},
            )
            self.assertEqual(runtime.projection()["node"]["generation"], 2)
        finally:
            runtime.close()

    def test_recovery_approvals_are_signed_and_bound_to_lost_generation(self):
        approval = make_recovery_approval(self.key, "node", 1, role="operator", approver_generation=1)
        authorization = make_recovery_authorization(self.key, "node", 1, "new-key", [approval])
        self.assertEqual(self.runtime.ingest([authorization])[0]["status"], "accepted")
        tampered = dict(approval, subject="other")
        bad = make_recovery_authorization(self.key, "other", 1, "new-key", [tampered])
        self.assertEqual(self.runtime.ingest([bad])[0]["reason"], "invalid-recovery-approval-signature")

    def test_lifecycle_families_require_shapes_and_recovery_provenance(self):
        identity = make_identity_generation(self.key, "node", 1, self.key.public_key)
        approval = make_recovery_approval(
            self.key, "node", 1, role="operator", approver_generation=1,
        )
        authorization = make_recovery_authorization(
            self.key, "node", 1, self.key.public_key, [approval],
            provenance=[{"source": "operator", "reason": "lost-key"}],
        )
        revoked = make_revocation(self.key, "node", 1, "lost-key")
        replacement = make_identity_generation(
            self.key, "node", 2, self.key.public_key, predecessor="node:1",
            recovery_authorization=authorization,
        )
        outcomes = self.runtime.ingest([identity, authorization, revoked, replacement])
        self.assertEqual([outcome["status"] for outcome in outcomes],
                         ["quarantined", "accepted", "accepted", "accepted"])
        self.assertEqual(outcomes[0]["reason"], "revoked-generation")
        self.assertEqual(self.runtime.projection()["node"]["generation"], 2)
        self.assertEqual(self.runtime.projection()["node"]["payload"]["provenance"],
                         [{"source": "operator", "reason": "lost-key"}])

    def test_revoked_generation_cannot_materialize_or_be_rebound_without_signed_approval(self):
        identity = make_identity_generation(self.key, "node", 1, self.key.public_key)
        revoked = make_revocation(self.key, "node", 1, "compromised")
        forged = make_identity_generation(self.key, "node", 2, self.key.public_key, predecessor="node:1")
        outcomes = self.runtime.ingest([identity, revoked, forged])
        self.assertEqual(outcomes[-1]["reason"], "missing-recovery-authorization")
        self.assertEqual(self.runtime.projection(), {})
        self.assertIn("revoked-generation", {item["reason"] for item in self.runtime.quarantine()})


class OpenBaoProviderTests(unittest.TestCase):
    def test_mock_command_materializes_atomic_0600_value_and_digest_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provider = root / "provider.py"
            provider.write_text(
                "import json, sys\n"
                "request = json.loads(sys.stdin.readline())\n"
                "print(json.dumps({'data': {request['field']: 'runtime-secret'}}))\n",
                encoding="utf-8",
            )
            output, ready = root / "credentials" / "db", root / "ready" / "db"
            result = subprocess.run([
                sys.executable, "-m", "arbor_registry_runtime.openbao_provider",
                "--path", "kv/data/arbor/db", "--field", "url",
                "--output", str(output), "--ready", str(ready),
                "--provider-command", sys.executable, str(provider),
            ], check=False, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(output.read_text(), "runtime-secret")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(ready.stat().st_mode), 0o644)
            self.assertNotIn("runtime-secret", ready.read_text())
            self.assertEqual(len(ready.read_text().strip()), 64)

    def test_openbao_shapes_require_string_field(self):
        self.assertEqual(_json_value({"data": {"url": "x"}}, "url"), "x")
        self.assertEqual(_json_value({"data": {"data": {"url": "x"}}}, "url"), "x")
        with self.assertRaises(ValueError):
            _json_value({"data": {"url": 1}}, "url")


if __name__ == "__main__":
    unittest.main()
