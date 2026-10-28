import io
import json
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

from arbor_registry_runtime.daemon import RegistryServer
from arbor_registry_runtime.manager_adapter import run
from arbor_registry_runtime.runtime import FileProvider, generate_keypair


class ManagerAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = {
            "stateDir": str(self.root / "state"),
            "socket": str(self.root / "registry.sock"),
            "transportSocket": str(self.root / "transport.sock"),
            "tokenFile": str(self.root / "token"),
            "keyDir": str(self.root / "keys"),
            "bootstrapAuthoritiesFile": str(self.root / "bootstrap.json"),
        }
        Path(self.config["tokenFile"]).write_text("t" * 32)
        self.server = RegistryServer(self.config)
        self.server.runtime.provider = FileProvider(self.root / "raw" / "history.jsonl")
        (self.root / "raw" / "history.jsonl").touch(mode=0o600)

    def tearDown(self):
        self.server.runtime.close()
        self.temp.cleanup()

    def request(self, operation, data):
        return self.server.handle({
            "token": "t" * 32,
            "protocol": "arbor-manager/runtime-adapter",
            "version": 1,
            "operation": operation,
            "data": data,
        })

    def test_init_self_is_idempotent_and_returns_only_public_identity_data(self):
        request = {"nodeId": "node-a", "domain": "nix-arbor-live-v1"}
        first = self.request("identity/init-self", request)
        key_path = Path(self.config["keyDir"]) / "node-a.private"
        private_key = key_path.read_text()

        self.assertEqual(first["status"], "accepted")
        self.assertTrue(first["localGenesis"])
        self.assertEqual(first["generation"], 1)
        self.assertEqual(self.request("identity/init-self", request), first)
        self.assertNotIn(private_key, json.dumps(first))
        self.assertEqual(self.server.runtime.status()["accepted"], 1)

    def test_init_self_rejects_conflicting_domain_without_replacing_key(self):
        self.request("identity/init-self", {"nodeId": "node-a", "domain": "domain-a"})
        key_path = Path(self.config["keyDir"]) / "node-a.private"
        old_key = key_path.read_bytes()

        response = self.request("identity/init-self", {"nodeId": "node-a", "domain": "domain-b"})

        self.assertEqual(response["status"], "conflict")
        self.assertEqual(key_path.read_bytes(), old_key)
        self.assertEqual(self.server.runtime.status()["accepted"], 1)

    def test_concurrent_init_self_uses_one_identity_and_one_genesis(self):
        request = {"nodeId": "node-a", "domain": "nix-arbor-live-v1"}
        barrier = threading.Barrier(8)
        results = []

        def initialize():
            barrier.wait()
            results.append(self.request("identity/init-self", request))

        workers = [threading.Thread(target=initialize) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        self.assertEqual(len(results), 8)
        self.assertEqual({result["publicFingerprint"] for result in results}, {results[0]["publicFingerprint"]})
        self.assertEqual({result["status"] for result in results}, {"accepted"})
        self.assertEqual(self.server.runtime.status()["accepted"], 1)

    def test_restart_preserves_identity_and_summary_uses_persisted_state(self):
        data = {"nodeId": "node-a", "domain": "domain-a"}
        original = self.request("identity/init-self", data)
        self.server.runtime.close()
        self.server = RegistryServer(self.config)
        self.server.runtime.provider = FileProvider(self.root / "raw" / "history.jsonl")
        self.assertEqual(self.request("identity/init-self", data), original)
        inspect = self.request("identity/inspect", {})
        summary = self.request("registry/summary", {"nodeId": "node-a"})
        self.assertEqual(inspect["publicFingerprint"], original["publicFingerprint"])
        self.assertEqual(summary["records"], {"total": 1, "accepted": 1, "quarantined": 0})
        self.assertEqual(summary["projection"]["total"], 1)

    def test_missing_key_never_reinitializes_existing_identity(self):
        data = {"nodeId": "node-a", "domain": "domain-a"}
        self.request("identity/init-self", data)
        private = Path(self.config["keyDir"]) / "node-a.private"
        public = Path(self.config["keyDir"]) / "node-a.public"
        public_before = public.read_bytes()
        private.unlink()
        self.assertEqual(self.request("identity/init-self", data)["status"], "conflict")
        self.assertFalse(private.exists())
        self.assertEqual(public.read_bytes(), public_before)
        self.assertEqual(self.request("identity/inspect", {"nodeId": "node-a"})["status"], "conflict")

    def test_existing_unclaimed_keys_are_preserved(self):
        key_dir = Path(self.config["keyDir"])
        generate_keypair(key_dir, "unclaimed")
        before = {p.name: p.read_bytes() for p in key_dir.iterdir()}
        self.assertEqual(self.request("identity/init-self", {"nodeId": "node-a", "domain": "domain-a"})["status"], "conflict")
        self.assertEqual({p.name: p.read_bytes() for p in key_dir.iterdir() if p.name in before}, before)
        self.assertFalse((key_dir / "node-a.private").exists())

    def test_second_identity_cannot_replace_the_local_root(self):
        self.request("identity/init-self", {"nodeId": "node-a", "domain": "domain-a"})
        self.assertEqual(self.request("identity/init-self", {"nodeId": "node-b", "domain": "domain-a"})["status"], "conflict")
        self.assertFalse((Path(self.config["keyDir"]) / "node-b.private").exists())
        self.assertEqual(self.request("identity/inspect", {})["nodeId"], "node-a")

    def test_key_loading_rejects_dangling_symlinks_and_insecure_files(self):
        key_dir = Path(self.config["keyDir"])
        key_dir.mkdir(mode=0o700)
        private = key_dir / "node-a.private"
        private.symlink_to(key_dir / "absent")
        request = {"nodeId": "node-a", "domain": "domain-a"}
        self.assertEqual(self.request("identity/init-self", request)["status"], "conflict")
        self.assertTrue(private.is_symlink())
        private.unlink()
        self.assertEqual(self.request("identity/init-self", request)["status"], "accepted")
        private.chmod(0o644)
        self.assertEqual(self.request("identity/init-self", request)["status"], "conflict")
        self.assertEqual(private.stat().st_mode & 0o777, 0o644)

    def test_invalid_request_has_no_identity_side_effects(self):
        for data in ({"nodeId": "../node", "domain": "domain-a"},
                     {"nodeId": "node-a", "domain": ""},
                     {"nodeId": "node-a", "domain": "domain-a", "key": "supplied"}):
            self.assertEqual(self.request("identity/init-self", data)["status"], "conflict")
        self.assertFalse(Path(self.config["keyDir"]).exists())
        self.assertEqual(self.request("identity/inspect", {})["initialized"], False)

    def test_runtime_adapter_sends_one_bounded_request_to_registry_socket(self):
        socket_path = self.root / "adapter.sock"
        seen = {}
        registry = self.server

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                seen.update(json.loads(self.rfile.readline()))
                self.wfile.write(json.dumps(registry.handle(seen)).encode() + b"\n")

        listener = socketserver.UnixStreamServer(str(socket_path), Handler)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        config_path = self.root / "config.json"
        token_path = self.root / "adapter-token"
        token_path.write_text("t" * 32)
        config_path.write_text(json.dumps({"socket": str(socket_path), "tokenFile": str(token_path)}))
        source = io.StringIO(json.dumps({
            "protocol": "arbor-manager/runtime-adapter", "version": 1,
            "operation": "identity/inspect", "data": {"nodeId": "node-a"},
        }) + "\n")
        output = io.StringIO()
        try:
            self.assertEqual(run(source, output, config_path), 0)
        finally:
            listener.shutdown()
            listener.server_close()
            thread.join()

        self.assertEqual(seen["token"], "t" * 32)
        self.assertEqual(seen["operation"], "identity/inspect")
        self.assertEqual(json.loads(output.getvalue())["nodeId"], "node-a")

    def test_runtime_adapter_rejects_unsupported_protocol_without_socket_access(self):
        source = io.StringIO(json.dumps({"protocol": "wrong", "version": 1}) + "\n")
        output = io.StringIO()
        self.assertNotEqual(run(source, output, self.root / "missing.json"), 0)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
