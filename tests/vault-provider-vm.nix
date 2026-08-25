{
  module,
  pkgs,
  upstreamModules,
}:
let
  runtimePackage = import ../runtime/package.nix {
    inherit (pkgs) lib python3Packages;
  };
in
pkgs.testers.nixosTest {
  name = "arbor-registry-vault-provider";
  nodes.machine =
    {
      ...
    }:
    {
      imports = upstreamModules ++ [ module ];
      system.stateVersion = "25.05";
      virtualisation.memorySize = 1024;

      environment.systemPackages = [ pkgs.openbao ];

      systemd.services.openbao-test = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          Environment = [
            "HOME=/root"
            "PATH=${pkgs.bash}/bin:${pkgs.coreutils}/bin:${pkgs.openbao}/bin"
          ];
          ExecStart = "${pkgs.openbao}/bin/bao server -dev -dev-root-token-id=arbor-test-root -dev-listen-address=0.0.0.0:8200";
          Restart = "on-failure";
        };
      };

      systemd.services.seed-openbao-secret = {
        wantedBy = [ "multi-user.target" ];
        after = [ "openbao-test.service" ];
        requires = [ "openbao-test.service" ];
        before = [ "arbor-vault-runtime-api-init.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          for attempt in $(seq 1 100); do
            if ${pkgs.curl}/bin/curl --fail --silent http://127.0.0.1:8200/v1/sys/health >/dev/null; then
              break
            fi
            sleep 0.1
          done
          install -d -m 0700 /run/arbor-test
          printf '%s\n' arbor-test-root >/run/arbor-test/token
          chmod 0600 /run/arbor-test/token
          BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=arbor-test-root \
            ${pkgs.openbao}/bin/bao kv put secret/arbor/db url=postgres://vm.example/db
        '';
      };

      systemd.services.api = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          cat "$CREDENTIALS_DIRECTORY/db-url" > /run/api-credential
        '';
      };

      cluster.vault.runtime = {
        enable = true;
        runtimePackage = runtimePackage;
        providers.local = {
          address = "http://127.0.0.1:8200";
          authMethod = "external";
          tokenFile = "/run/arbor-test/token";
        };
        requirements.db = {
          provider = "local";
          path = "secret/data/arbor/db";
          field = "url";
          credentialName = "db-url";
        };
        bindings.api = {
          requirement = "db";
          service = "api";
        };
      };
    };
  testScript = ''
    start_all()
    machine.wait_for_unit("openbao-test.service")
    machine.wait_for_unit("seed-openbao-secret.service")
    machine.wait_for_unit("arbor-vault-runtime-api-init.service")
    machine.succeed("systemctl start api.service")
    machine.succeed("test \"$(cat /run/api-credential)\" = 'postgres://vm.example/db'")
    machine.succeed("test \"$(stat -c %a /run/arbor-vaultd/credentials/api)\" = 600")
  '';
}
