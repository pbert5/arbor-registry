import json

TOKEN = "/run/arbor-test/socket-token"
start_all()
for node in (node_a, node_b):
    node.wait_for_unit("arbor-registry-transport.service", timeout=120)
    node.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
    node.wait_until_succeeds("test -s " + TOKEN, timeout=120)

def call(node, socket_path, operation, **extra):
    value = {"operation": operation, **extra}
    script = ("import json,socket; value=" + repr(value) + "; "
              "value['token']=open(" + repr(TOKEN) + ").read().strip(); "
              "s=socket.socket(socket.AF_UNIX); s.connect(" + repr(socket_path) + "); "
              "s.sendall((json.dumps(value)+'\\n').encode()); print(s.recv(1048576).decode())")
    return json.loads(node.succeed("python3 -c %r" % script))

def transport(node, operation, **extra):
    return call(node, "/run/arbor-registry-transport/transport.sock", operation, **extra)

def registry(node, operation, **extra):
    return call(node, "/run/arbor-registry/registry.sock", operation, **extra)

node_a.succeed("python3 /etc/arbor-test/fixture.py")
authorities = node_a.succeed("cat /run/arbor-test/bootstrap-authorities.json").strip()
for node in (node_a, node_b):
    node.succeed("printf '%%s\\n' %r > /run/arbor-test/bootstrap-authorities.json" % authorities)
    node.succeed("chmod 0644 /run/arbor-test/bootstrap-authorities.json")

status_a = transport(node_a, "status")
assert status_a["ok"] and status_a["databaseAddresses"]["registry"]
address = json.dumps({"registry": status_a["databaseAddresses"]["registry"]}).replace('"', '\\"')
dropin = ('[Service]\\nEnvironment="ARBOR_REGISTRY_DATABASE_ADDRESSES=%s" '
          'Environment="ARBOR_REGISTRY_BOOTSTRAP_PEERS=/ip4/10.42.0.10/tcp/4001/p2p/%s"'
          % (address, status_a["peerId"]))
node_b.succeed("mkdir -p /run/systemd/system/arbor-registry-transport.service.d")
node_b.succeed("printf '%%s\\n' %r > /run/systemd/system/arbor-registry-transport.service.d/acceptance.conf" % dropin)
node_b.succeed("systemctl daemon-reload; systemctl restart arbor-registry-transport.service")
node_b.wait_for_unit("arbor-registry-transport.service", timeout=120)
for node in (node_a, node_b):
    node.succeed("systemctl start arbor-registry.service")
    node.wait_for_unit("arbor-registry.service", timeout=120)
    node.wait_until_succeeds("test -S /run/arbor-registry/registry.sock", timeout=120)

fixture = json.loads(node_a.succeed("cat /run/arbor-test/records.json"))
by_id = {item["recordId"]: item for item in fixture}
def accepted(node):
    return registry(node, "accepted")["records"]
def quarantined(node):
    return registry(node, "quarantine")["records"]
def has_record(node, record_id):
    return any(item.get("recordId") == record_id for item in accepted(node))
def wait_until(node, predicate, label):
    last = None
    for _ in range(120):
        last = predicate()
        if last:
            return
        node.succeed("sleep 0.25")
    raise AssertionError(label + ": " + json.dumps(last))

# Both directions are consumed by the installed Registry sync workers.
assert not transport(node_a, "append", stream="registry", event=by_id["live-a"])["duplicate"]
assert transport(node_a, "append", stream="registry", event=by_id["live-a"])["duplicate"]
wait_until(node_a, lambda: has_record(node_a, "live-a"), "A did not auto-consume A record")
wait_until(node_b, lambda: has_record(node_b, "live-a"), "B did not auto-consume A record")
assert not transport(node_b, "append", stream="registry", event=by_id["live-b"])["duplicate"]
wait_until(node_a, lambda: has_record(node_a, "live-b"), "A did not auto-consume B record")
wait_until(node_b, lambda: has_record(node_b, "live-b"), "B did not auto-consume B record")

# The invalid entry must not prevent the following valid entry from landing.
transport(node_a, "append", stream="registry", event=by_id["live-bad"])
transport(node_a, "append", stream="registry", event=by_id["live-after-bad"])
wait_until(node_b, lambda: any(item["record"].get("recordId") == "live-bad" and item["reason"] == "unknown-schema" for item in quarantined(node_b)), "bad record was not quarantined")
wait_until(node_b, lambda: has_record(node_b, "live-after-bad"), "valid record after bad record did not continue")

# The transport stays available while B's Registry is down, then the worker
# catches up from its durable cursor after the Registry restart.
node_b.succeed("systemctl stop arbor-registry.service")
transport(node_a, "append", stream="registry", event=by_id["live-outage"])
node_b.succeed("systemctl start arbor-registry.service")
node_b.wait_for_unit("arbor-registry.service", timeout=120)
wait_until(node_b, lambda: has_record(node_b, "live-outage"), "Registry outage catch-up failed")

before = registry(node_b, "status")["runtime"]["providerCursor"]
node_b.succeed("systemctl restart arbor-registry.service")
node_b.wait_for_unit("arbor-registry.service", timeout=120)
transport(node_a, "append", stream="registry", event=by_id["live-after-restart"])
wait_until(node_b, lambda: has_record(node_b, "live-after-restart"), "restart cursor did not resume")
after = registry(node_b, "status")["runtime"]["providerCursor"]
assert before != after, (before, after)
assert len([item for item in accepted(node_a) if item["recordId"] == "live-a"]) == 1
assert len([item for item in accepted(node_b) if item["recordId"] == "live-a"]) == 1
print("LIVE A->B/B->A automatic consumption: PASS")
print("LIVE duplicate idempotence: PASS")
print("LIVE bad-record quarantine and continue: PASS")
print("LIVE outage catch-up: PASS")
print("LIVE Registry restart cursor resume: PASS")
