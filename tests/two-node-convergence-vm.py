import json
import base64

TOKEN = "/run/arbor-test/socket-token"
start_all()

# B has no participant target wants.  Assert this startup gate before any
# convergence activity: neither transport nor Registry may have opened.
node_b.succeed("! systemctl is-active --quiet arbor-registry-transport.service")
node_b.succeed("! systemctl is-active --quiet arbor-registry.service")
node_b.succeed("test ! -e /run/arbor-registry-transport/transport.sock")
node_b.succeed("test ! -e /run/arbor-registry/registry.sock")
print("STARTUP B-held-before-A-readiness: PASS")

node_a.wait_for_unit("arbor-registry-transport.service", timeout=120)
node_a.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
node_a.wait_until_succeeds("test -s " + TOKEN, timeout=120)

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
    node.succeed("mkdir -p /run/arbor-test")
    node.succeed("printf '%%s\\n' %r > /run/arbor-test/bootstrap-authorities.json" % authorities)
    node.succeed("chmod 0644 /run/arbor-test/bootstrap-authorities.json")

status_a = transport(node_a, "status")
assert status_a.get("ok") is True, status_a
assert status_a.get("peerId"), status_a
assert status_a.get("databaseAddresses", {}).get("registry"), status_a
address = status_a["databaseAddresses"]["registry"]
database_addresses = json.dumps({"registry": address}, separators=(",", ":"))
# systemd parses the outer quotes and the escaped JSON quotes into the exact
# compact JSON object expected by transport/registryd.mjs.
systemd_database_addresses = database_addresses.replace('"', '\\"')
dropin = (
    "[Service]\n"
    'Environment="ARBOR_REGISTRY_DATABASE_ADDRESSES=%s"\n'
    'Environment="ARBOR_REGISTRY_BOOTSTRAP_PEERS=/ip4/10.42.0.10/tcp/4001/p2p/%s"\n'
    % (systemd_database_addresses, status_a["peerId"])
)

def write_text_deterministically(node, path, value):
    encoded = base64.b64encode(value.encode()).decode()
    node.succeed("echo %s | base64 -d > %s" % (encoded, path))

node_b.succeed("mkdir -p /run/systemd/system/arbor-registry-transport.service.d")
write_text_deterministically(node_b, "/run/systemd/system/arbor-registry-transport.service.d/acceptance.conf", dropin)
node_b.succeed("systemctl daemon-reload")
node_b.succeed("systemctl cat arbor-registry-transport.service | grep -F 'ARBOR_REGISTRY_DATABASE_ADDRESSES=' >/dev/null")
node_b.succeed("systemctl show arbor-registry-transport.service -p Environment --value | grep -F 'ARBOR_REGISTRY_DATABASE_ADDRESSES=' >/dev/null")
node_b.succeed("systemd-analyze verify arbor-registry-transport.service")
print("STARTUP B-drop-in-real-newlines-and-systemd-verify: PASS")

# This is B's first transport start/open, and it happens only after the
# complete A status gate and configuration verification above.
node_b.succeed("systemctl start arbor-registry-transport.service")
node_b.wait_for_unit("arbor-registry-transport.service", timeout=120)
node_b.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
status_b = transport(node_b, "status")
assert status_b.get("ok") is True and status_b.get("peerId"), status_b
assert status_b.get("databaseAddresses") == status_a["databaseAddresses"], (status_a, status_b)
print("STARTUP B-configured-and-actual-DB-equals-A: PASS")
node_b.succeed("systemctl restart arbor-registry-transport.service")
node_b.wait_for_unit("arbor-registry-transport.service", timeout=120)
node_b.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock", timeout=120)
status_b_after_transport_restart = transport(node_b, "status")
assert status_b_after_transport_restart["databaseAddresses"] == status_a["databaseAddresses"]
node_b.succeed("test -s /var/lib/arbor-registry-transport/transport-bootstrap.json")
print("STARTUP B-DB-address-persistence-after-restart: PASS")

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

# Both directions are consumed by the installed Registry sync workers.  The
# originating node uses the Registry API, which validates, persists, and
# publishes the record to the raw transport.
assert registry(node_a, "ingest", records=[by_id["live-a"]])["outcomes"][0]["status"] == "accepted"
wait_until(node_a, lambda: has_record(node_a, "live-a"), "A did not auto-consume A record")
wait_until(node_b, lambda: has_record(node_b, "live-a"), "B did not auto-consume A record")
assert registry(node_b, "ingest", records=[by_id["live-b"]])["outcomes"][0]["status"] == "accepted"
wait_until(node_a, lambda: has_record(node_a, "live-b"), "A did not auto-consume B record")
wait_until(node_b, lambda: has_record(node_b, "live-b"), "B did not auto-consume B record")

# Replaying a published transport entry is harmless and does not duplicate
# the accepted projection.
assert transport(node_a, "append", stream="registry", event=by_id["live-a"])["duplicate"]

# The invalid entry must not prevent the following valid entry from landing.
assert registry(node_a, "ingest", records=[by_id["live-bad"]])["outcomes"][0]["status"] == "quarantined"
assert registry(node_a, "ingest", records=[by_id["live-after-bad"]])["outcomes"][0]["status"] == "accepted"
wait_until(node_b, lambda: any(item["record"].get("recordId") == "live-bad" and item["reason"] == "unknown-schema" for item in quarantined(node_b)), "bad record was not quarantined")
wait_until(node_b, lambda: has_record(node_b, "live-after-bad"), "valid record after bad record did not continue")

# The transport stays available while B's Registry is down, then the worker
# catches up from its durable cursor after the Registry restart.
node_b.succeed("systemctl stop arbor-registry.service")
assert registry(node_a, "ingest", records=[by_id["live-outage"]])["outcomes"][0]["status"] == "accepted"
node_b.succeed("systemctl start arbor-registry.service")
node_b.wait_for_unit("arbor-registry.service", timeout=120)
node_b.wait_until_succeeds("test -S /run/arbor-registry/registry.sock", timeout=120)
wait_until(node_b, lambda: has_record(node_b, "live-outage"), "Registry outage catch-up failed")

before = registry(node_b, "status")["runtime"]["providerCursor"]
node_b.succeed("systemctl restart arbor-registry.service")
node_b.wait_for_unit("arbor-registry.service", timeout=120)
node_b.wait_until_succeeds("test -S /run/arbor-registry/registry.sock", timeout=120)
assert registry(node_a, "ingest", records=[by_id["live-after-restart"]])["outcomes"][0]["status"] == "accepted"
wait_until(node_b, lambda: has_record(node_b, "live-after-restart"), "restart cursor did not resume")
after = registry(node_b, "status")["runtime"]["providerCursor"]
assert before != after, (before, after)
status_b_after_restart = transport(node_b, "status")
assert status_b_after_restart["databaseAddresses"] == status_a["databaseAddresses"]
assert len([item for item in accepted(node_a) if item["recordId"] == "live-a"]) == 1
assert len([item for item in accepted(node_b) if item["recordId"] == "live-a"]) == 1
print("LIVE Registry A/B ingest -> remote automatic consumption: PASS")
print("LIVE duplicate idempotence: PASS")
print("LIVE bad-record quarantine and continue: PASS")
print("LIVE outage catch-up: PASS")
print("LIVE Registry restart cursor resume: PASS")
