import json
import os
from pathlib import Path

from arbor_registry_runtime import RuntimeKey, generate_keypair, make_identity_generation, make_lifecycle_record

root = Path("/run/arbor-test")
root.mkdir(mode=0o700, exist_ok=True)
keys = root / "keys"
keys.mkdir(mode=0o700, exist_ok=True)
authority = generate_keypair(keys, "root-a")
(root / "bootstrap-authorities.json").write_text(json.dumps({"root-a": authority.public_key}) + "\n")

def identity(name):
    return make_identity_generation(authority, name, 1, authority.public_key)

def relationship(record_id, source, target, kind="parent", status="active"):
    return make_lifecycle_record(authority, "relationship", record_id, {
        "relationshipId": record_id, "from": source, "to": target, "kind": kind,
        "status": status, "scope": ["observe"], "autonomy": "dependent",
        "authorityRoot": "root-a",
    })

records = [
    identity("root-a"), identity("root-b"), identity("child"), identity("grandchild"),
    relationship("root-a-child", "root-a", "child"),
    relationship("root-b-child", "root-b", "child", status="standby"),
    relationship("child-grandchild", "child", "grandchild"),
    relationship("child-peer", "child", "root-b", "peer"),
]
(root / "records.json").write_text(json.dumps(records) + "\n")
