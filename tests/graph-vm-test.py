import json
import sys

TOKEN_FILE = "/run/arbor-test/runtime/socket-token"

sys.path.insert(0, "/run/current-system/sw/lib/python3.14/site-packages")

start_all()
nodes = (root_a, root_b, child, grandchild)
def wait_for_health(node):
    node.wait_until_succeeds("python3 -c %r" % (
        "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
        f"s.sendall((json.dumps({{'operation':'health','token':open('{TOKEN_FILE}').read().strip()}})+'\\n').encode()); "
        "v=json.loads(s.recv(65536)); assert v.get('ok') is True and v.get('status') == 'ok', v;"
    ), timeout=120)

for node in (root_a,):
    node.succeed("systemctl start arbor-registry-transport.service")
    node.wait_for_unit("arbor-registry-transport.service", timeout=120)
    node.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
    node.wait_until_succeeds(f"test -s {TOKEN_FILE}", timeout=120)

root_a.succeed("python3 /etc/arbor-test/graph.py")
authorities = root_a.succeed("cat /run/arbor-test/bootstrap-authorities.json").strip()
for node in nodes:
    node.succeed("mkdir -p /run/arbor-test; printf '%%s\\n' %r > /run/arbor-test/bootstrap-authorities.json" % authorities)
    node.succeed("chmod 0755 /run/arbor-test; chmod 0644 /run/arbor-test/bootstrap-authorities.json")

def request(node, operation, **extra):
    script = ("import json,socket; value=" + repr({"operation": operation, **extra}) + "; "
              f"value['token']=open('{TOKEN_FILE}').read().strip(); "
              "s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
              "s.sendall((json.dumps(value)+'\\n').encode()); print(s.recv(1048576).decode())")
    return json.loads(node.succeed("python3 -c %r" % script))

def transport_request(node, operation, **extra):
    script = ("import json,socket; value=" + repr({"operation": operation, **extra}) + "; "
              f"value['token']=open('{TOKEN_FILE}').read().strip(); "
              "s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry-transport/transport.sock'); "
              "s.sendall((json.dumps(value)+'\\n').encode()); print(s.recv(1048576).decode())")
    return json.loads(node.succeed("python3 -c %r" % script))

records = json.loads(root_a.succeed("cat /run/arbor-test/records.json"))
by_id = {record["recordId"]: record for record in records}
local_records = {
    root_a: [by_id["root-a"], by_id["root-a-child"], by_id["root-a-child-split"], by_id["root-a-child-rejoin"]],
    root_b: [by_id["root-b"], by_id["root-b-child"]],
    child: [by_id["child"], by_id["child-grandchild"], by_id["child-peer"]],
    grandchild: [by_id["grandchild"]],
}

# Transport replication is observable before a foreign Registry is started.
# The raw record is deliberately not submitted to that Registry by this test.
root_a.succeed("systemctl start arbor-registry.service")
root_a.wait_for_unit("arbor-registry.service", timeout=120)
wait_for_health(root_a)
assert request(root_a, "ingest", records=local_records[root_a])["ok"]
transport_status = transport_request(root_a, "status")
assert transport_status["ok"] and transport_status["databaseAddresses"]["registry"]
address = transport_status["databaseAddresses"]["registry"]
for node in nodes[1:]:
    peer = transport_status["peerId"]
    address_json = json.dumps({"registry": address}).replace('"', '\\"')
    env = 'Environment="ARBOR_REGISTRY_DATABASE_ADDRESSES=%s" Environment="ARBOR_REGISTRY_BOOTSTRAP_PEERS=/ip4/10.42.0.10/tcp/4001/p2p/%s"' % (address_json, peer)
    node.succeed("mkdir -p /run/systemd/system/arbor-registry-transport.service.d")
    node.succeed("printf '%%s\\n' '[Service]' '%s' > /run/systemd/system/arbor-registry-transport.service.d/graph.conf" % env)
    node.succeed("systemctl daemon-reload; systemctl start arbor-registry-transport.service")
    node.wait_for_unit("arbor-registry-transport.service", timeout=120)

for node in nodes[1:]:
    node.succeed("test -S /run/arbor-registry-transport/transport.sock")
print("MATRIX foreign-raw-state-before-local-genesis: PASS")

# Each node performs only its own local-origin Registry ingest. Every other
# record below must arrive through the transport provider and sync worker.
for node in nodes[1:]:
    node.succeed("systemctl start arbor-registry.service")
    node.wait_for_unit("arbor-registry.service", timeout=120)
    wait_for_health(node)
for node in nodes[1:]:
    outcome = request(node, "ingest", records=[local_records[node][0]])
    assert outcome["ok"] and outcome["outcomes"][0]["status"] == "accepted", outcome
for node in (root_a, root_b, child):
    outcome = request(node, "ingest", records=local_records[node][1:])
    assert outcome["ok"] and all(item["status"] == "accepted" for item in outcome["outcomes"]), outcome
assert request(root_a, "ingest", records=[by_id["root-a"]])["outcomes"][0]["status"] == "accepted"
print("MATRIX independent-self-root-genesis-and-local-origin-ingest: PASS")

for node in nodes[1:]:
    node.succeed("systemctl restart arbor-registry.service")
    node.wait_for_unit("arbor-registry.service", timeout=120)
    wait_for_health(node)
    node.succeed("systemctl is-active arbor-registry-transport.service arbor-registry.service")
print("MATRIX transport-replication-and-remote-consumer: PASS")

def wait_for_record(node, record_id):
    node.wait_until_succeeds("python3 -c %r" % (
        "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
        f"s.sendall((json.dumps({{'operation':'accepted','token':open('{TOKEN_FILE}').read().strip()}})+'\\n').encode()); "
        f"x=json.loads(s.recv(1048576)); assert any(item.get('recordId') == '{record_id}' for item in x.get('records', [])), x;"), timeout=120)

for node in nodes:
    for record in records:
        wait_for_record(node, record["recordId"])
print("MATRIX join-split-rejoin-multiple-parents-two-graph-bridge: PASS")
print("MATRIX transport-does-not-imply-trust: PASS")

status = json.loads(root_a.succeed("python3 -c %r" % (
    "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
    "s.sendall(b'{\"operation\":\"status\"}\\n'); print(s.recv(1048576).decode())",)))
assert status["ok"]
root_a.succeed("test -s /var/lib/arbor-registry/registry.sqlite3")
root_a.succeed("systemctl restart arbor-registry.service")
root_a.wait_for_unit("arbor-registry.service", timeout=120)
wait_for_health(root_a)
print("MATRIX persisted-registry-state-restart: PASS")

root_a.succeed("systemctl stop arbor-registry-transport.service")
root_a.wait_until_succeeds("! systemctl is-active --quiet arbor-registry-transport.service")
root_a.succeed("systemctl start arbor-registry-transport.service")
root_a.wait_for_unit("arbor-registry-transport.service", timeout=120)
print("MATRIX transport-service-failure-recovery: PASS")
TOKEN_FILE = "/run/arbor-test/runtime/socket-token"
