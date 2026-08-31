import json
import sys

sys.path.insert(0, "/run/current-system/sw/lib/python3.14/site-packages")

start_all()
nodes = (root_a, root_b, child, grandchild)
def wait_for_health(node):
    node.wait_until_succeeds("python3 -c %r" % (
        "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
        "s.sendall((json.dumps({'operation':'health','token':open('/run/arbor-registry/socket-token').read().strip()})+'\\n').encode()); "
        "v=json.loads(s.recv(65536)); assert v.get('ok') is True and v.get('status') == 'ok', v;"
    ), timeout=120)

for node in nodes:
    node.wait_for_unit("arbor-registry-transport.service", timeout=120)
    node.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
    node.wait_until_succeeds("test -s /run/arbor-registry/socket-token", timeout=120)

root_a.succeed("python3 /etc/arbor-test/graph.py")
authorities = root_a.succeed("cat /run/arbor-test/bootstrap-authorities.json").strip()
for node in nodes:
    node.succeed("mkdir -p /run/arbor-test; printf '%%s\\n' %r > /run/arbor-test/bootstrap-authorities.json" % authorities)
    node.succeed("chmod 0755 /run/arbor-test; chmod 0644 /run/arbor-test/bootstrap-authorities.json")
    node.succeed("systemctl start arbor-registry.service")
    node.wait_for_unit("arbor-registry.service", timeout=120)
    wait_for_health(node)
root_a.succeed("systemctl restart arbor-registry.service")
root_a.wait_for_unit("arbor-registry.service", timeout=120)
wait_for_health(root_a)

def request(node, operation, **extra):
    script = ("import json,socket; value=" + repr({"operation": operation, **extra}) + "; "
              "value['token']=open('/run/arbor-registry/socket-token').read().strip(); "
              "s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); "
              "s.sendall((json.dumps(value)+'\\n').encode()); print(s.recv(1048576).decode())")
    return json.loads(node.succeed("python3 -c %r" % script))

def transport_request(node, operation, **extra):
    script = ("import json,socket; value=" + repr({"operation": operation, **extra}) + "; "
              "value['token']=open('/run/arbor-registry/socket-token').read().strip(); "
              "s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry-transport/transport.sock'); "
              "s.sendall((json.dumps(value)+'\\n').encode()); print(s.recv(1048576).decode())")
    return json.loads(node.succeed("python3 -c %r" % script))

records = json.loads(root_a.succeed("cat /run/arbor-test/records.json"))
response = request(root_a, "ingest", records=records)
assert response["ok"] and all(item["status"] == "accepted" for item in response["outcomes"]), response
assert request(root_a, "ingest", records=records)["ok"]
print("MATRIX graph-ingest-and-duplicate: PASS")

transport_status = transport_request(root_a, "status")
assert transport_status["ok"] and transport_status["databaseAddresses"]["registry"]
for node in nodes[1:]:
    peer = transport_status["peerId"]
    address = transport_status["databaseAddresses"]["registry"]
    node.succeed("mkdir -p /run/systemd/system/arbor-registry-transport.service.d")
    env = "Environment=ARBOR_REGISTRY_DATABASE_ADDRESSES=%s Environment=ARBOR_REGISTRY_BOOTSTRAP_PEERS=/ip4/10.42.0.10/tcp/4001/p2p/%s" % (address, peer)
    node.succeed("printf '%%s\\n' '[Service]' '%s' > /run/systemd/system/arbor-registry-transport.service.d/graph.conf" % env)
    node.succeed("systemctl daemon-reload; systemctl restart arbor-registry-transport.service")
    node.wait_for_unit("arbor-registry-transport.service", timeout=120)
for node in nodes[1:]:
    node.wait_until_succeeds("python3 -c %r" % (
        "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry-transport/transport.sock'); "
        "s.sendall((json.dumps({'operation':'list','stream':'registry','token':open('/run/arbor-registry/socket-token').read().strip()})+'\\n').encode()); "
        "x=json.loads(s.recv(1048576)); assert x.get('ok') and x.get('records')",), timeout=120)
print("MATRIX cross-node-transport-convergence: PASS")

for node in nodes[1:]:
    node.succeed("systemctl restart arbor-registry.service")
    node.wait_for_unit("arbor-registry.service", timeout=120)
    wait_for_health(node)
    result = request(node, "ingest", records=records)
    assert result["ok"] and all(item["status"] == "accepted" for item in result["outcomes"]), result
    node.succeed("systemctl is-active arbor-registry-transport.service arbor-registry.service")
print("MATRIX four-isolated-registry-and-transport-services: PASS")

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
