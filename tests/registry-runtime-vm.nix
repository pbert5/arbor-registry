{ module, pkgs }:
pkgs.testers.nixosTest {
  name = "arbor-registry-production-runtime";
  nodes.machine =
    { ... }:
    {
      imports = [ module ];
      system.stateVersion = "25.05";
      virtualisation.memorySize = 1536;
      cluster.registry.runtime.enable = true;
      environment.systemPackages = [
        pkgs.jq
        pkgs.python3
      ];
    };
  testScript = ''
    import json

    def refresh():
        machine.succeed("systemctl reset-failed arbor-runtime-status.service; systemctl start arbor-runtime-status.service")

    registry_health = "python3 -c 'import json,socket; t=open(\"/run/arbor-registry/socket-token\").read().strip(); s=socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(\"/run/arbor-registry/registry.sock\"); s.sendall((json.dumps({\"operation\":\"health\",\"token\":t})+chr(10)).encode()); print(s.recv(65536).decode())' | jq -e '.ok == true and .status == \"ok\"'"

    machine.succeed("systemctl start arbor-participant.target")
    machine.wait_for_unit("arbor-participant.target")
    machine.wait_for_unit("arbor-registry-transport.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock")
    machine.wait_until_succeeds(registry_health)
    machine.succeed("systemctl is-enabled arbor-participant.target arbor-registry.service arbor-registry-transport.service")
    refresh()
    healthy = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    machine.log("STATUS " + json.dumps(healthy))
    machine.succeed("cat /run/arbor/doctor/status.json")
    assert healthy["registry"]["installed"] and healthy["registry"]["running"] and healthy["registry"]["ready"]
    assert healthy["transport"]["installed"] and healthy["transport"]["running"]
    machine.succeed("systemctl stop arbor-registry.service")
    machine.wait_until_succeeds("! systemctl is-active arbor-registry.service")
    machine.wait_until_succeeds("! (" + registry_health + ")")
    refresh()
    degraded = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    machine.log("DEGRADED " + json.dumps(degraded))
    assert degraded["status"] == "degraded" and degraded["healthy"] is False, degraded
    assert degraded["registry"] != healthy["registry"], (healthy, degraded)
    assert degraded["registry"]["running"] == 0 and degraded["ready"] is False
    machine.succeed("systemctl start arbor-registry.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_until_succeeds(registry_health)
    refresh()
    restored = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    assert restored["status"] == "healthy" and restored["healthy"] is True, restored
    assert restored["registry"] != degraded["registry"], (degraded, restored)
    assert restored["registry"]["ready"] is True
    assert "token" not in json.dumps(restored).lower()
  '';
}
