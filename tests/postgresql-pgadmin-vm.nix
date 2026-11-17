{ modules, pkgs }:
pkgs.testers.nixosTest {
  name = "arbor-registry-postgresql-pgadmin";
  nodes.machine = { ... }: {
    imports = modules;
    system.stateVersion = "25.05";
    virtualisation.memorySize = 2048;
    cluster.registry.runtime.enable = true;
    services.postgresql.settings.port = 5544;
    cluster.registry.postgresql = {
      enable = true;
      pgadmin = {
        enable = true;
        initialEmail = "admin@example.com";
        initialPasswordFile = "/run/pgadmin-test-password";
      };
    };
    systemd.tmpfiles.rules = [ "f /run/pgadmin-test-password 0600 root root - testpassword" ];
    environment.systemPackages = [
      pkgs.curl
      pkgs.jq
    ];
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_for_unit("pgadmin.service")
    machine.wait_until_succeeds("curl -fsS http://127.0.0.1:5050/login >/dev/null")
    machine.succeed("ss -ltn | grep '127.0.0.1:5050'")
    machine.fail("ss -ltn | grep -E '(0.0.0.0|\\[::\\]):5050'")
    machine.succeed("runuser -u arbor-registry -- psql -h /run/postgresql -p 5544 -U arbor-registry -d arbor_registry -v ON_ERROR_STOP=1 -c 'CREATE TABLE readonly_test (value integer); INSERT INTO readonly_test VALUES (1)'")
    machine.succeed("runuser -u pgadmin -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -v ON_ERROR_STOP=1 -c 'SELECT * FROM readonly_test'")
    machine.fail("runuser -u pgadmin -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -v ON_ERROR_STOP=1 -c 'INSERT INTO readonly_test VALUES (2)'")
    machine.fail("runuser -u pgadmin -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -v ON_ERROR_STOP=1 -c 'CREATE TABLE forbidden (value integer)'")
    machine.fail("runuser -u arbor-registry -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -c 'SELECT 1'")
    machine.succeed("systemctl restart postgresql.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_until_succeeds("runuser -u arbor-registry -- psql -h /run/postgresql -p 5544 -U arbor-registry -d arbor_registry -c 'SELECT 1'")
    machine.succeed("test $(stat -c %a /run/pgadmin-test-password) = 600")
  '';
}
