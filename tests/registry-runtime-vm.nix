{ module, pkgs }:
pkgs.testers.nixosTest {
  name = "arbor-registry-production-runtime";
  nodes.machine =
    { config, ... }:
    {
      imports = [ module ];
      system.stateVersion = "25.05";
      virtualisation.memorySize = 1536;
      cluster.registry.runtime.enable = true;
      environment.systemPackages = [
        pkgs.jq
        pkgs.python3
        config.cluster.registry.runtime.runtimePackage
      ];
    };
  testScript = ''
    import json
    import shlex

    def refresh():
        machine.succeed("systemctl reset-failed arbor-runtime-status.service; systemctl start arbor-runtime-status.service")

    machine.succeed("systemctl start arbor-participant.target")
    machine.wait_for_unit("arbor-participant.target")
    machine.wait_for_unit("arbor-registry-transport.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.succeed("test -S /run/arbor-registry/registry.sock")
    machine.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock")
    machine.succeed("systemctl is-enabled arbor-participant.target arbor-registry.service arbor-registry-transport.service")
    refresh()
    healthy = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    machine.log("STATUS " + json.dumps(healthy))
    machine.succeed("cat /run/arbor/doctor/status.json")
    assert healthy["registry"]["installed"] and healthy["registry"]["running"] and healthy["registry"]["ready"]
    assert healthy["transport"]["installed"] and healthy["transport"]["running"]
    initial_token_digest = machine.succeed("sha256sum /run/arbor-registry/socket-token")
    machine.succeed("systemctl stop arbor-registry.service")
    machine.wait_until_succeeds("! systemctl is-active --quiet arbor-registry.service")
    refresh()
    degraded = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    machine.log("DEGRADED " + json.dumps(degraded))
    assert degraded["registry"]["running"] == 0 and degraded["ready"] is False
    machine.succeed("systemctl start arbor-registry.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry/registry.sock")
    refresh()
    restored = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    assert restored["registry"]["ready"] is True
    assert machine.succeed("sha256sum /run/arbor-registry/socket-token") == initial_token_digest
    assert machine.succeed("stat -c %a /run/arbor-registry/socket-token").strip() == "600"
    assert "token" not in json.dumps(restored).lower()

    def adapter(operation, data):
        request = json.dumps({"protocol": "arbor-manager/runtime-adapter", "version": 1,
                              "operation": operation, "data": data})
        return json.loads(machine.succeed("printf %s " + shlex.quote(request) + " | arbor-registry-manager-adapter"))

    assert adapter("identity/inspect", {})["initialized"] is False
    identity = {"nodeId": "vm-local", "domain": "vm-local-domain"}
    initialized = adapter("identity/init-self", identity)
    assert initialized["status"] == "accepted" and initialized["generation"] == 1
    assert initialized["localGenesis"] and initialized["selfRooted"]
    assert adapter("identity/init-self", identity) == initialized
    machine.succeed("systemctl restart arbor-registry.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry/registry.sock")
    inspected = adapter("identity/inspect", {})
    assert inspected["publicFingerprint"] == initialized["publicFingerprint"]
    assert adapter("registry/summary", {"nodeId": "vm-local"})["records"] == {"total": 1, "accepted": 1, "quarantined": 0}
    machine.log("MANAGER_ADAPTER_GENESIS_RESTART_PASS")
  '';
}
