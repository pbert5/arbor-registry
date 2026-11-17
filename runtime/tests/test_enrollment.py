import copy
import io
import json
import socketserver
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from arbor_registry_runtime.daemon import RegistryServer
from arbor_registry_runtime.manager_adapter import run
from arbor_registry_runtime.runtime import (
    FileProvider, _digest, generate_keypair, load_keypair, make_revocation,
)


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.authority_key = generate_keypair(self.root / "approver" / "keys", "authority")
        (self.root / "bootstrap").write_text(json.dumps({"authority": self.authority_key.public_key}))
        (self.root / "token").write_text("t" * 32)
        self.services = {}
        self.addCleanup(lambda: [s.runtime.close() for s in self.services.values()])
        self.join = self.start("join")
        self.approver = self.start("approver")
        self.data = {"nodeId": "child", "authorityId": "authority", "platform": "linux"}

    def start(self, name):
        path = self.root / name
        if name in self.services:
            self.services[name].runtime.close()
        s = RegistryServer({"stateDir": str(path / "state"), "keyDir": str(path / "keys"),
                            "tokenFile": str(self.root / "token"), "bootstrapAuthoritiesFile": str(self.root / "bootstrap")})
        s.runtime.provider = FileProvider(path / "raw" / "journal")
        (path / "raw" / "journal").touch(mode=0o600)
        self.services[name] = s
        return s

    def call(self, server, op, data):
        return server.handle({"token": "t" * 32, "protocol": "arbor-manager/runtime-adapter",
                              "version": 1, "operation": op, "data": data})

    def request(self):
        r = self.call(self.join, "enrollment/request", self.data)
        self.assertEqual(r["status"], "accepted")
        return r["request"]

    def approve(self, request):
        return self.call(self.approver, "enrollment/approve", {
            "authorityId": "authority", "requestDigest": _digest(request), "request": request})

    def finish(self, approval):
        return self.call(self.join, "enrollment/finish", {"nodeId": "child", "approval": approval})

    def test_ceremony_retries_restart_and_strict_public_scope(self):
        request = self.request()
        self.assertEqual(self.request(), request)
        self.assertEqual(self.call(self.join, "identity/init-self", {"nodeId": "child", "domain": "x"})["status"], "conflict")
        self.assertEqual(self.call(self.join, "enrollment/approve", {
            "authorityId": "authority", "request": request, "requestDigest": _digest(request)})["status"], "conflict")
        approval = self.approve(request)["approval"]
        self.assertEqual(self.approve(request)["approval"], approval)
        self.assertEqual(self.approver.runtime.status()["accepted"], 1)
        self.join.runtime.ingest([approval], retain=False)  # replication before operator imports the receipt
        self.assertFalse(self.call(self.join, "identity/inspect", {})["initialized"])
        self.assertEqual(self.finish(approval)["status"], "accepted")
        self.join = self.start("join")
        self.assertEqual(self.finish(approval)["status"], "accepted")
        status = self.call(self.join, "enrollment/status", {"authorityId": "authority"})
        self.assertEqual((status["canApprove"], status["enrollmentState"]), (False, "enrolled"))
        identity = self.call(self.join, "identity/inspect", {})
        self.assertEqual((identity["initialized"], identity["nodeId"], identity["selfRooted"],
                          identity["parents"], identity["peers"]), (True, "child", False, 0, 0))
        self.assertNotIn("child", self.join.runtime.authority_issuers)

    def test_delayed_approval_survives_renewal_and_expiry(self):
        with patch("arbor_registry_runtime.enrollment.time.time", return_value=100):
            original = self.request()
            approval = self.approve(original)["approval"]
        with patch("arbor_registry_runtime.enrollment.time.time", return_value=1000):
            renewed = self.request()
            self.assertNotEqual(_digest(original), _digest(renewed))
            self.assertEqual(self.approve(original)["approval"], approval)
            self.assertEqual(self.approve(renewed)["status"], "conflict")
            self.assertEqual(self.finish(approval)["status"], "accepted")

    def test_expired_or_changed_request_cannot_first_approve(self):
        request = self.request()
        with patch("arbor_registry_runtime.enrollment.time.time", return_value=request["expiresAt"]):
            self.assertEqual(self.approve(request)["status"], "conflict")
        for field, value in (("subject", "other"), ("platform", "macos"), ("requestedParent", "other"),
                             ("publicKey", []), ("extra", "field"), ("version", True)):
            self.assertEqual(self.approve({**request, field: value})["status"], "conflict", field)
        self.assertEqual(self.call(self.approver, "enrollment/approve", {
            "authorityId": "authority", "request": request, "requestDigest": "0" * 64})["status"], "conflict")
        self.assertEqual(self.approver.runtime.status()["records"], 0)

    def test_untrusted_or_revoked_authority_cannot_publish_or_finish(self):
        self.assertEqual(self.call(self.join, "enrollment/request", {**self.data, "authorityId": "unknown"})["status"], "conflict")
        request = self.request()
        approval = self.approve(request)["approval"]
        revocation = make_revocation(self.authority_key, "authority", 1, "retired")
        for service in (self.join, self.approver):
            self.assertEqual(service.runtime.ingest([revocation])[0]["status"], "accepted")
            self.assertFalse(self.call(service, "enrollment/status", {"authorityId": "authority"})["authorityTrusted"])
        self.assertEqual(self.finish(approval)["status"], "conflict")
        self.assertEqual(self.approve(request)["status"], "conflict")

    def test_mutated_approval_and_other_root_rejected_before_storage(self):
        approval = self.approve(self.request())["approval"]
        for field, value in (("platform", "other"), ("publicKey", "x" * 43),
                             ("approvedBy", "other"), ("enrollmentRequestDigest", "a" * 64)):
            changed = copy.deepcopy(approval)
            changed["payload"][field] = value
            self.assertEqual(self.finish(changed)["status"], "conflict")
        self.assertEqual(self.finish({**approval, "signature": "x" * 86})["status"], "conflict")
        self.assertEqual(self.join.runtime.status()["records"], 0)

    def test_failed_first_request_resumes_with_exact_same_key(self):
        with patch("arbor_registry_runtime.enrollment.make_enrollment_request", side_effect=OSError):
            self.assertEqual(self.call(self.join, "enrollment/request", self.data)["status"], "unavailable")
        public = load_keypair(self.join.key_dir, "child").public_key
        self.join = self.start("join")
        self.assertEqual(self.call(self.join, "enrollment/request", {**self.data, "nodeId": "other"})["status"], "conflict")
        self.assertEqual(self.request()["publicKey"], public)

    def test_materialization_or_transport_failure_can_retry_without_partial_approval(self):
        request = self.request()
        for obj, method in ((self.approver.runtime, "_materialize"), (self.approver.runtime.provider, "append")):
            with patch.object(obj, method, side_effect=RuntimeError("interrupted")):
                self.assertEqual(self.approve(request)["status"], "unavailable")
            self.assertEqual(self.approver.runtime.status()["records"], 0)
        self.assertEqual(self.approve(request)["status"], "accepted")

    def test_adapter_limits_public_output_and_checks_operation_subject(self):
        request = self.request()
        response = {"format": "arbor-manager/runtime-response", "version": 1, "status": "accepted",
                    "operation": "enrollment/request", "nodeId": "child", "request": request,
                    "requestDigest": _digest(request), "publicFingerprint": "unexpected-data"}

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.rfile.readline()
                self.wfile.write(json.dumps(response).encode() + b"\n")

        socket_path = self.root / "adapter.sock"
        config = self.root / "adapter.json"
        config.write_text(json.dumps({"tokenFile": str(self.root / "token"), "socket": str(socket_path)}))
        source = json.dumps({"protocol": "arbor-manager/runtime-adapter", "version": 1,
                             "operation": "enrollment/request", "data": self.data})
        with socketserver.UnixStreamServer(str(socket_path), Handler) as listener:
            worker = threading.Thread(target=listener.serve_forever)
            worker.start()
            try:
                output = io.StringIO()
                self.assertEqual(run(io.StringIO(source), output, config), 0)
                self.assertNotIn("unexpected-data", output.getvalue())
                response["nodeId"] = "other"
                output = io.StringIO()
                self.assertEqual(run(io.StringIO(source), output, config), 1)
                self.assertEqual(output.getvalue(), "")
            finally:
                listener.shutdown()
                worker.join()

    def test_local_genesis_and_unclaimed_keys_cannot_be_enrolled(self):
        self.assertEqual(self.call(self.join, "identity/init-self", {"nodeId": "child", "domain": "x"})["status"], "accepted")
        self.assertEqual(self.call(self.join, "enrollment/request", self.data)["status"], "conflict")
        self.assertFalse(self.call(self.join, "enrollment/status", {"authorityId": "child"})["canApprove"])
        self.assertEqual(self.call(self.approver, "enrollment/request", self.data)["status"], "conflict")


if __name__ == "__main__":
    unittest.main()
