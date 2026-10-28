import json
import os
import sys
from pathlib import Path

runtime_bin = Path(os.path.realpath("/run/current-system/sw/bin/arbor-registryd"))
sys.path.insert(0, str(runtime_bin.parents[1] / "lib/python3.14/site-packages"))

from arbor_registry_runtime import generate_keypair, make_identity_generation

root = Path("/run/arbor-test")
keys = root / "keys"
keys.mkdir(mode=0o700, parents=True, exist_ok=True)
authority = generate_keypair(keys, "root-a")
(root / "bootstrap-authorities.json").write_text(json.dumps({"root-a": authority.public_key}) + "\n")

def envelope(record_id, schema, payload):
    record = {"protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1,
              "recordVersion": 1, "recordId": record_id, "generation": 1,
              "predecessor": None, "issuer": authority.issuer, "schema": schema,
              "payload": payload}
    return {**record, "signature": authority.sign(record)}

records = [
    make_identity_generation(authority, "live-a", 1, authority.public_key),
    make_identity_generation(authority, "live-b", 1, authority.public_key),
    envelope("live-bad", "future-record", {"id": "bad"}),
    make_identity_generation(authority, "live-after-bad", 1, authority.public_key),
    make_identity_generation(authority, "live-outage", 1, authority.public_key),
    make_identity_generation(authority, "live-after-restart", 1, authority.public_key),
]
(root / "records.json").write_text(json.dumps(records) + "\n")
