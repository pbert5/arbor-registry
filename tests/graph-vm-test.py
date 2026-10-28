import json
import sys
import base64

TOKEN_FILE = "/run/arbor-test/runtime/socket-token"

sys.path.insert(0, "/run/current-system/sw/lib/python3.14/site-packages")

start_all()
nodes = (root_a, root_b, child, grandchild)
for node in nodes:
    node.wait_for_unit("multi-user.target")
    node.succeed("! systemctl is-active --quiet arbor-registry-transport.service")

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
# Publish a tampered signed envelope directly to raw transport.
invalid_record = dict(by_id["root-a"], recordId="tampered-transport-record")
assert transport_request(root_a, "append", stream="registry", event=invalid_record)["ok"]
transport_status = transport_request(root_a, "status")
assert transport_status["ok"] and transport_status["databaseAddresses"]["registry"]
address = transport_status["databaseAddresses"]["registry"]
assert f'/ip4/10.42.0.10/tcp/4001/p2p/{transport_status["peerId"]}' in transport_status["listenMultiaddrs"], transport_status
peer_ids = {transport_status["peerId"]}
for node in nodes[1:]:
    node.succeed("ping -c 1 -W 3 10.42.0.10")
    peer = transport_status["peerId"]
    address_json = json.dumps({"registry": address}, separators=(",", ":")).replace('"', '\\"')
    bootstrap = "/ip4/10.42.0.10/tcp/4001/p2p/" + peer
    dropin = ('[Service]\nEnvironment="ARBOR_REGISTRY_DATABASE_ADDRESSES=%s"\n'
              'Environment="ARBOR_REGISTRY_BOOTSTRAP_PEERS=%s"\n' % (address_json, bootstrap))
    node.succeed("mkdir -p /run/systemd/system/arbor-registry-transport.service.d")
    node.succeed("echo %s | base64 -d > /run/systemd/system/arbor-registry-transport.service.d/graph.conf" % base64.b64encode(dropin.encode()).decode())
    node.succeed("systemctl daemon-reload; systemd-analyze verify arbor-registry-transport.service")
    check_env = ("import shlex,subprocess,json; env=dict(item.split('=',1) for item in shlex.split(subprocess.check_output(['systemctl','show','arbor-registry-transport.service','-p','Environment','--value'],text=True))); "
                 "assert env['ARBOR_REGISTRY_BOOTSTRAP_PEERS']==%r, env; assert json.loads(env['ARBOR_REGISTRY_DATABASE_ADDRESSES'])==%r, env" % (bootstrap, {"registry": address}))
    node.succeed("python3 -c %r" % check_env)
    node.succeed("systemctl start arbor-registry-transport.service")
    node.wait_for_unit("arbor-registry-transport.service", timeout=120)

for node in nodes[1:]:
    try:
        node.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
    except Exception:
        print(node.succeed("ip -br address; ip route; systemctl show arbor-registry-transport.service -p Environment; journalctl -u arbor-registry-transport.service --no-pager"))
        print(root_a.succeed("ip -br address; ip route; journalctl -u arbor-registry-transport.service --no-pager"))
        print(transport_request(root_a, "status"))
        raise
    status = transport_request(node, "status")
    assert status["peerId"] not in peer_ids and status["databaseAddresses"] == transport_status["databaseAddresses"], status
    peer_ids.add(status["peerId"])
    assert status["bootstrapPeers"] == ["/ip4/10.42.0.10/tcp/4001/p2p/" + transport_status["peerId"]], status
    assert transport_status["peerId"] in status["connectedPeers"], status
    node.wait_until_succeeds("python3 -c %r" % (
        "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry-transport/transport.sock'); "
        f"s.sendall((json.dumps({{'operation':'list','stream':'registry','cursor':'v2:begin','limit':100,'token':open('{TOKEN_FILE}').read().strip()}})+'\\n').encode()); "
        "x=json.loads(s.recv(1048576)); assert x.get('ok') and any(r.get('event',{}).get('recordId') == 'root-a' for r in x.get('records',[])), x;"), timeout=120)
print("MATRIX foreign-raw-state-before-local-genesis: PASS")
root_b.wait_until_succeeds("python3 -c %r" % (
    "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry-transport/transport.sock'); "
    f"s.sendall((json.dumps({{'operation':'list','stream':'registry','cursor':'v2:begin','limit':100,'token':open('{TOKEN_FILE}').read().strip()}})+'\\n').encode()); "
    "x=json.loads(s.recv(1048576)); assert any(r.get('event',{}).get('recordId') == 'tampered-transport-record' for r in x.get('records',[])), x;"), timeout=120)

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
    try:
        node.wait_until_succeeds("python3 -c %r" % (
            "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
            f"s.sendall((json.dumps({{'operation':'accepted','token':open('{TOKEN_FILE}').read().strip()}})+'\\n').encode()); "
            f"x=json.loads(s.recv(1048576)); assert any(item.get('recordId') == '{record_id}' for item in x.get('records', [])), x;"), timeout=120)
    except Exception:
        print('DIAGNOSTIC missing record', record_id, 'transport status', transport_request(node, 'status'))
        print('DIAGNOSTIC transport records', transport_request(node, 'list', stream='registry', cursor='v2:begin', limit=100))
        print('DIAGNOSTIC registry status', request(node, 'status'))
        print('DIAGNOSTIC quarantine', request(node, 'quarantine'))
        raise

for node in nodes:
    for record in records:
        wait_for_record(node, record["recordId"])
print("MATRIX join-split-rejoin-multiple-parents-two-graph-bridge: PASS")
root_b.wait_until_succeeds("python3 -c %r" % (
    "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
    f"s.sendall((json.dumps({{'operation':'quarantine','token':open('{TOKEN_FILE}').read().strip()}})+'\\n').encode()); "
    "x=json.loads(s.recv(1048576)); assert any(item.get('record',{}).get('recordId') == 'tampered-transport-record' and item.get('reason') == 'invalid-signature' for item in x.get('records',[])), x;"), timeout=120)
assert not any(item.get("recordId") == "tampered-transport-record" for item in request(root_b, "accepted")["records"])
assert "tampered-transport-record" not in request(root_b, "projection")["records"]
print("MATRIX transport-does-not-imply-trust: PASS (invalid signature quarantined)")

status = request(root_a, "status")
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
