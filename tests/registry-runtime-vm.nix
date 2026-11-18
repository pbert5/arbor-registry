{ module, pkgs }:
let
  customTokenInit =
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        module
        {
          system.stateVersion = "25.05";
          cluster.registry.runtime = {
            enable = true;
            tokenFile = "/run/arbor-custom/child/socket-token";
          };
        }
      ];
    }).config.systemd.services.arbor-registry-token.serviceConfig.ExecStart;
  rejected =
    registry: transport:
    let
      evaluated = import (pkgs.path + "/nixos/lib/eval-config.nix") {
        system = pkgs.stdenv.hostPlatform.system;
        modules = [
          module
          {
            system.stateVersion = "25.05";
            cluster.registry.runtime = {
              enable = true;
              stateDirectory = registry;
              transportStateDirectory = transport;
            };
          }
        ];
      };
    in
    pkgs.lib.any (
      item: !item.assertion && pkgs.lib.hasPrefix "Registry and transport state directories" item.message
    ) evaluated.config.assertions;
in
assert rejected "same" "same";
assert rejected "same" "same/child";
assert rejected "same/child" "same";
assert rejected "a/../b" "other";
assert !(rejected "registry" "transport");
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
    assert machine.succeed("id -u arbor-registry") != machine.succeed("id -u arbor-registry-transport")
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
    assert machine.succeed("stat -c %a /run/arbor-registry/socket-token").strip() == "640"
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
    # Existing custom files are not silently made group-readable.
    machine.succeed("install -d -o arbor-registry -g arbor-registry -m 0750 /run/arbor-custom /run/arbor-custom/child")
    machine.succeed("printf fixture > /run/arbor-custom/child/socket-token; chown arbor-registry:arbor-registry /run/arbor-custom/child/socket-token; chmod 0600 /run/arbor-custom/child/socket-token")
    machine.fail("${pkgs.util-linux}/bin/runuser -u arbor-registry -- ${customTokenInit}")
    assert machine.succeed("stat -c %a /run/arbor-custom/child/socket-token").strip() == "600"
    machine.succeed("chmod 0640 /run/arbor-custom/child/socket-token")
    machine.succeed("chmod 0770 /run/arbor-custom")
    machine.fail("${pkgs.util-linux}/bin/runuser -u arbor-registry -- ${customTokenInit}")
    machine.succeed("chmod 0750 /run/arbor-custom")
    machine.succeed("${pkgs.util-linux}/bin/runuser -u arbor-registry -- ${customTokenInit}")
    machine.succeed("mv /run/arbor-custom /run/arbor-custom-real; ln -s /run/arbor-custom-real /run/arbor-custom")
    machine.fail("${pkgs.util-linux}/bin/runuser -u arbor-registry -- ${customTokenInit}")

    # Transport can use the shared IPC token but cannot sign pair messages or read keys.
    machine.fail("${pkgs.util-linux}/bin/runuser -u arbor-registry-transport -- test -x /var/lib/arbor-registry")
    machine.fail("${pkgs.util-linux}/bin/runuser -u arbor-registry-transport -- test -w /run/arbor-registry")
    probe = "import json,socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); t=open('/run/arbor-registry/socket-token').read().strip(); s.sendall((json.dumps({'operation':'pair/identity','token':t})+'\\n').encode()); print(json.loads(s.makefile().readline())['code'])"
    command = "${pkgs.util-linux}/bin/runuser -u arbor-registry-transport -- python3 -c " + shlex.quote(probe)
    assert machine.succeed(command).strip() == "operator_required"

    # Simulate an upgrade from the old UID with actual populated transport state.
    machine.succeed("systemctl stop arbor-registry.service arbor-registry-transport.service")
    machine.succeed("cp /var/lib/arbor-registry-transport/libp2p.key /tmp/transport-key-before")
    machine.succeed("cp /run/arbor-registry/socket-token /tmp/socket-token-before")
    # Run the actual transport under the old account and populated store first.
    dropin = "/run/systemd/system/arbor-registry-transport.service.d"
    legacy = "[Service]\nUser=arbor-registry\n"
    machine.succeed("mkdir -p " + dropin + "; printf %s " + shlex.quote(legacy) + " > " + dropin + "/legacy.conf; systemctl daemon-reload")
    machine.succeed("systemctl start arbor-registry-transport.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock")
    old_pid = machine.succeed("systemctl show -p MainPID --value arbor-registry-transport.service").strip()
    assert machine.succeed("stat -c %u /proc/" + old_pid).strip() == machine.succeed("id -u arbor-registry").strip()
    machine.succeed("systemctl stop arbor-registry-transport.service")
    machine.fail("kill -0 " + old_pid)
    machine.succeed("cmp /tmp/transport-key-before /var/lib/arbor-registry-transport/libp2p.key")
    machine.succeed("rm " + dropin + "/legacy.conf; systemctl daemon-reload")
    machine.succeed("chmod 0600 /run/arbor-registry/socket-token")
    machine.succeed("systemctl restart arbor-registry-token.service")
    machine.succeed("cmp /tmp/socket-token-before /run/arbor-registry/socket-token")
    assert machine.succeed("stat -c %a /run/arbor-registry/socket-token").strip() == "640"
    machine.succeed("systemctl start arbor-registry.service")
    machine.wait_for_unit("arbor-registry-transport.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry/registry.sock")
    machine.succeed("cmp /tmp/transport-key-before /var/lib/arbor-registry-transport/libp2p.key")
    machine.succeed("test $(stat -c %U /var/lib/arbor-registry-transport/libp2p.key) = arbor-registry-transport")
    assert adapter("identity/inspect", {})["publicFingerprint"] == initialized["publicFingerprint"]
    machine.succeed("systemctl restart arbor-registry-transport.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock")
    machine.succeed("cmp /tmp/transport-key-before /var/lib/arbor-registry-transport/libp2p.key")
    # Roll back to the old service user, verify the same transport key, then restore.
    machine.succeed("systemctl stop arbor-registry.service arbor-registry-transport.service")
    machine.succeed("printf %s " + shlex.quote(legacy) + " > " + dropin + "/legacy.conf; systemctl daemon-reload")
    machine.succeed("systemctl start arbor-registry-transport.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry-transport/transport.sock")
    machine.succeed("cmp /tmp/transport-key-before /var/lib/arbor-registry-transport/libp2p.key")
    machine.succeed("test $(stat -c %U /var/lib/arbor-registry-transport/libp2p.key) = arbor-registry")
    machine.succeed("systemctl stop arbor-registry-transport.service")
    machine.succeed("rm " + dropin + "/legacy.conf; systemctl daemon-reload")
    machine.succeed("systemctl start arbor-registry.service")
    machine.wait_until_succeeds("test -S /run/arbor-registry/registry.sock")
    assert adapter("identity/inspect", {})["publicFingerprint"] == initialized["publicFingerprint"]
    machine.succeed("cmp /tmp/transport-key-before /var/lib/arbor-registry-transport/libp2p.key")
    machine.log("MANAGER_ADAPTER_GENESIS_RESTART_PASS")
  '';
}
