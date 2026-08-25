import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nacl.signing import SigningKey

from arbor_registry_runtime import FileProvider, OrbitDBProvider, Provider, Runtime, RuntimeKey, canonical_json, generate_keypair
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
