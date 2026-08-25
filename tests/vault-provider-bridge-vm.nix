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
  name = "arbor-registry-vault-provider-bridge";
  nodes.machine =
    {
      ...
    }:
    {
      imports = upstreamModules ++ [ module ];
      system.stateVersion = "25.05";
      virtualisation.memorySize = 1024;

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
            if ${pkgs.curl}/bin/curl --fail --silent http://127.0.0.1:8200/v1/sys/health >/dev/null; then break; fi
            sleep 0.1
          done
          install -d -m 0700 /run/arbor-test
          printf '%s\n' arbor-test-root >/run/arbor-test/token
          chmod 0600 /run/arbor-test/token
          BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=arbor-test-root \
            ${pkgs.openbao}/bin/bao kv put secret/arbor/db \
            url=postgres://vm.example/db token=vm-token
        '';
      };

      systemd.services.arbor-vault-runtime-api-db-init.after = [ "seed-openbao-secret.service" ];
      systemd.services.arbor-vault-runtime-api-token-init.after = [ "seed-openbao-secret.service" ];

      systemd.services.api = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          cat "$CREDENTIALS_DIRECTORY/db-url" > /run/api-db
          cat "$CREDENTIALS_DIRECTORY/api-token" > /run/api-token
        '';
      };

      cluster.vault.runtime = {
        enable = true;
        useUpstreamVaultd = true;
        useProviderBridge = true;
        runtimePackage = runtimePackage;
        refreshInterval = 1;
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
        requirements.token = {
          provider = "local";
          path = "secret/data/arbor/db";
          field = "token";
          credentialName = "api-token";
        };
        bindings.api-db = {
          requirement = "db";
          service = "api";
        };
        bindings.api-token = {
          requirement = "token";
          service = "api";
        };
      };
    };
  testScript = ''
    start_all()
    machine.wait_for_unit("seed-openbao-secret.service")
    machine.wait_for_unit("arbor-vault-runtime-api-bridge.service")
    machine.succeed("test \"$(cat /run/systemd-vaultd/secrets/api.service.json)\" = '{\"api-token\":\"vm-token\",\"db-url\":\"postgres://vm.example/db\"}'")
    machine.succeed("systemctl start api.service")
    machine.succeed("test \"$(cat /run/api-db)\" = 'postgres://vm.example/db'")
    machine.succeed("test \"$(cat /run/api-token)\" = 'vm-token'")
    machine.succeed("test \"$(stat -c %a /run/systemd-vaultd/secrets/api.service.json)\" = 400")
  '';
}
