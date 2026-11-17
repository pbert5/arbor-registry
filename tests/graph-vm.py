import json
import os
import sys
from pathlib import Path

runtime_bin = Path(os.path.realpath("/run/current-system/sw/bin/arbor-registryd"))
sys.path.insert(0, str(runtime_bin.parents[1] / "lib/python3.14/site-packages"))

from arbor_registry_runtime import generate_keypair, make_local_genesis

root = Path("/run/arbor-test")
root.mkdir(mode=0o700, exist_ok=True)
keys = root / "keys"
keys.mkdir(mode=0o700, exist_ok=True)
identities = {
    name: generate_keypair(keys, name)
    for name in ("root-a", "root-b", "child", "grandchild")
}
(root / "bootstrap-authorities.json").write_text(
    json.dumps({name: key.public_key for name, key in identities.items()}) + "\n"
)

def relationship(record_id, signer, source, target, root_name, kind="parent", status="active"):
    record = {
        "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
        "recordVersion": 1, "recordId": record_id, "generation": 1,
        "predecessor": None, "issuer": signer.issuer, "schema": "relationship",
        "payload": {
            "relationshipId": record_id, "from": source, "to": target, "kind": kind,
            "status": status, "scope": ["observe"], "autonomy": "dependent",
            "authorityRoot": root_name,
        },
    }
    return {**record, "signature": signer.sign(record)}

records = [
    make_local_genesis(identities["root-a"], "root-a", "domain-a"),
    make_local_genesis(identities["root-b"], "root-b", "domain-b"),
    make_local_genesis(identities["child"], "child", "domain-child"),
    make_local_genesis(identities["grandchild"], "grandchild", "domain-grandchild"),
    relationship("root-a-child", identities["root-a"], "root-a", "child", "root-a"),
    relationship("root-b-child", identities["root-b"], "root-b", "child", "root-b", status="standby"),
    relationship("child-grandchild", identities["child"], "child", "grandchild", "child"),
    relationship("child-peer", identities["child"], "child", "root-b", "child", "peer"),
    relationship("root-a-child-split", identities["root-a"], "root-a", "child", "root-a", status="suspended"),
    relationship("root-a-child-rejoin", identities["root-a"], "root-a", "child", "root-a", status="active"),
]
(root / "records.json").write_text(json.dumps(records) + "\n")
