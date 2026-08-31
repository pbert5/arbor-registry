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

    machine.succeed("systemctl start arbor-participant.target")
    machine.wait_for_unit("arbor-participant.target")
    machine.wait_for_unit("arbor-registry-transport.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.succeed("test -S /run/arbor-registry/registry.sock")
    machine.succeed("test -S /run/arbor-registry-transport/transport.sock")
    machine.succeed("systemctl is-enabled arbor-participant.target arbor-registry.service arbor-registry-transport.service")
    refresh()
    healthy = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    assert healthy["registry"]["installed"] and healthy["registry"]["running"] and healthy["registry"]["ready"]
    assert healthy["transport"]["installed"] and healthy["transport"]["running"]
    machine.succeed("systemctl stop arbor-registry.service")
    refresh()
    degraded = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    assert degraded["registry"]["running"] is False and degraded["ready"] is False
    machine.succeed("systemctl start arbor-registry.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry/registry.sock")
    refresh()
    restored = json.loads(machine.succeed("cat /run/arbor/doctor/status.json"))
    assert restored["registry"]["ready"] is True
    assert "token" not in json.dumps(restored).lower()
  '';
}
