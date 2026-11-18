import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from arbor_registry_runtime.daemon import RegistryServer
from arbor_registry_runtime.pairing import Pairing
from arbor_registry_runtime.runtime import FileProvider, Runtime, generate_keypair


class ExistingRootPair(unittest.TestCase):
    session = "ab" * 32

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = self.root("r640-0")
        self.child = self.root("eVolver")
        self.a = self.parent.handle("identity", {})
        self.b = self.child.handle("identity", {})

    def root(self, name):
        path = Path(self.temp.name) / name
        key = generate_keypair(path / "keys", name)
        rt = Runtime(path / "db", FileProvider(path / "raw" / "records"), {}, node_key=key)
        self.addCleanup(rt.close)
        rt.local_genesis(name, "live")
        return Pairing(rt, path / "keys")

    def request(self):
        return self.child.handle("request", {"parent": self.a, "session": self.session})

    def approve(self, request):
        return self.parent.handle("approve", {"request": request, "session": self.session})

    def accept(self, approval):
        return self.child.handle("accept", {"approval": approval, "session": self.session})

    def test_interrupted_parent_commit_recovers_exact_receipt_even_after_expiry(self):
        req = self.request()
        approval = self.approve(req)
        cert = self.accept(approval)
        parent, child = self.a["identity"], self.b["identity"]
        self.assertFalse(self.parent.status(parent, child)["paired"])
        self.assertTrue(self.child.status(parent, child)["paired"])
        self.assertEqual(self.child.runtime.state_summary(child)["localIdentity"]["parentCount"], 1)
        with patch("arbor_registry_runtime.pairing.time.time", return_value=req["expires"] + 3600):
            for _ in range(2):
                self.assertEqual(self.parent.handle("commit", {"certificate": cert}), self.child.status(parent, child))
        for pairing in (self.parent, self.child):
            self.assertIn(cert, pairing.runtime.accepted())
            self.assertEqual(pairing.runtime.projection()[cert["recordId"]]["payload"], cert["payload"])
            self.assertFalse(pairing.status(child, parent)["paired"])
            self.assertEqual(set(pairing.runtime.public_keys), set(pairing.runtime.local_authorities))
            self.assertEqual(len(pairing.runtime.provider.fetch()), 1)
            self.assertIsNone(pairing.runtime._edge(cert))

    def test_wrong_session_realm_and_role_fail_closed(self):
        req = self.request()
        for changes in ({"session": "cd" * 32}, {"parent": self.b}, {"extra": 1},
                        {"child": {**self.b, "domain": "other"}}, {"type": "approve"}):
            with self.assertRaises(ValueError):
                self.approve({**req, **changes})
        with self.assertRaises(ValueError):
            self.child.handle("approve", {"request": req, "session": self.session})
        with self.assertRaises(ValueError):
            self.child.handle("request", {"parent": {**self.a, "domain": "other"}, "session": self.session})
        with patch("arbor_registry_runtime.pairing.time.time", return_value=req["expires"]):
            with self.assertRaises(ValueError):
                self.approve(req)
        approval = self.approve(req)
        with self.assertRaises(ValueError):
            self.child.handle("accept", {"approval": approval, "session": "cd" * 32})
        with self.assertRaises(ValueError):
            self.parent.handle("request", {"parent": self.b, "session": "cd" * 32})
        self.assertFalse(self.child.status(self.a["identity"], self.b["identity"])["paired"])

    def test_certificate_and_successor_cannot_enter_through_transport(self):
        cert = self.accept(self.approve(self.request()))
        rt = self.parent.runtime
        self.assertEqual(rt.ingest([cert])[0]["status"], "quarantined")
        self.assertEqual(len(rt.provider.fetch()), 1)
        self.assertNotIn(cert["recordId"], rt.projection())
        for changes in ({"acceptedAt": cert["acceptedAt"] + 1}, {"issuer": self.a["identity"]},
                        {"payload": {**cert["payload"], "kind": "peer"}},
                        {"signature": cert["approval"]["request"]["signature"]}):
            with self.assertRaises(ValueError):
                self.parent.handle("commit", {"certificate": {**cert, **changes}})
        self.parent.handle("commit", {"certificate": cert})
        forged = copy.deepcopy(cert)
        del forged["type"], forged["approval"], forged["signature"]
        forged.update(issuer=self.a["identity"], generation=2, recordVersion=2,
                      predecessor=cert["recordId"])
        forged["payload"].update(authorityRoot=self.a["identity"], status="severed")
        forged["signature"] = rt.node_key.sign(forged)
        self.assertEqual(rt.ingest([forged], retain=False)[0]["status"], "quarantined")
        self.assertTrue(self.parent.status(self.a["identity"], self.b["identity"])["paired"])

    def test_configured_key_must_match_pair_identity(self):
        self.child.runtime.public_keys[self.a["identity"]] = self.b["publicKey"]
        with self.assertRaises(ValueError):
            self.request()
        del self.child.runtime.public_keys[self.a["identity"]]
        self.child.runtime.public_keys["other-name"] = self.a["publicKey"]
        with self.assertRaises(ValueError):
            self.request()

    def test_token_alone_cannot_sign(self):
        server = RegistryServer.__new__(RegistryServer)
        server.runtime, server.key_dir, server.token = self.parent.runtime, self.parent.key_dir, "t" * 32
        req = {"operation": "pair/identity", "token": server.token}
        self.assertEqual(server.handle(req, peer_uid=os.geteuid() + 1)["code"], "operator_required")
        self.assertEqual(server.handle(req, peer_uid=os.geteuid())["result"], self.a)
        self.assertFalse(server.handle({**req, "token": "invalid"}, peer_uid=0)["ok"])
