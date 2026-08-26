import unittest

from arbor_registry_runtime import FileProvider, Runtime, RuntimeKey, make_public_record
from arbor_registry_runtime.registryctl import manager_snapshot
from arbor_registry_runtime.runtime import SigningKey


class RegistryCtlSurfaceTests(unittest.TestCase):
    def test_node_bound_typed_publications_and_digest_changes(self):
        key = RuntimeKey("node-a", SigningKey.generate())
        record = make_public_record(key, "configuration-intent", "intent-1", {"node": "node-a", "revision": "r1"})
        self.assertEqual(record["schema"], "configuration-intent")
        first = manager_snapshot({"nodes": {"node-a": {"hostname": "a", "token": "omit", "code": "omit"}}})
        second = manager_snapshot({"nodes": {"node-a": {"hostname": "b"}}})
        self.assertNotEqual(first["snapshotDigest"], second["snapshotDigest"])
        self.assertNotIn("token", first["snapshot"]["nodes"]["node-a"])
        self.assertNotIn("code", first["snapshot"]["nodes"]["node-a"])

    def test_runtime_rejects_unauthorized_recovery_and_accepts_current(self):
        import tempfile
        from pathlib import Path
        from arbor_registry_runtime import make_recovery_approval, make_recovery_authorization

        with tempfile.TemporaryDirectory() as directory:
            root = RuntimeKey("root", SigningKey.generate())
            operator = RuntimeKey("operator", SigningKey.generate())
            runtime = Runtime(Path(directory) / "state", FileProvider(Path(directory) / "raw"),
                              {"root": root.public_key, "operator": operator.public_key},
                              authority_issuers={"root"}, approver_roles={"operator": {"root"}},
                              recovery_thresholds={"operator": 1, "parent": 0, "peer": 0})
            approval = make_recovery_approval(root, "node", 1, role="operator", approver_generation=1)
            authorization = make_recovery_authorization(root, "node", 1, "new-key", [approval])
            self.assertEqual(runtime.ingest([authorization])[0]["status"], "accepted")
            stale = make_recovery_approval(operator, "node-stale", 2, role="operator", approver_generation=1)
            bad = make_recovery_authorization(root, "node-stale", 1, "new-key", [stale])
            self.assertEqual(runtime.ingest([bad])[0]["reason"], "unbound-recovery-approval")
            unauthorized = make_recovery_approval(operator, "node-unauthorized", 1, role="peer", approver_generation=1)
            bad_role = make_recovery_authorization(root, "node-unauthorized", 1, "new-key", [unauthorized])
            self.assertEqual(runtime.ingest([bad_role])[0]["reason"], "untrusted-recovery-approver")
            runtime.close()


if __name__ == "__main__":
    unittest.main()
