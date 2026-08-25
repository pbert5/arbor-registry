{
  module,
  upstreamModules,
  pkgs,
}:
pkgs.testers.nixosTest {
  name = "arbor-registry-vault-upstream";
  nodes.machine = {
    config,
    ...
  }:
    {
      imports = upstreamModules ++ [ module ];
      system.stateVersion = "25.05";
      virtualisation.memorySize = 1024;

      systemd.services.seed-vaultd-secret = {
        wantedBy = [ "multi-user.target" ];
        before = [ "api.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          install -d -m 0755 /run/systemd-vaultd/secrets
          printf '%s\n' '{"db-url":"postgres://runtime.example/db"}' > /run/systemd-vaultd/secrets/api.service.json
          chmod 0400 /run/systemd-vaultd/secrets/api.service.json
        '';
      };

      systemd.services.api = {
        wantedBy = [ "multi-user.target" ];
        after = [ "seed-vaultd-secret.service" "systemd-vaultd.service" ];
        requires = [ "seed-vaultd-secret.service" "systemd-vaultd.socket" ];
        script = ''
          cat "$CREDENTIALS_DIRECTORY/db-url" > /run/api-credential
        '';
      };

      cluster.vault.runtime = {
        enable = true;
        useUpstreamVaultd = true;
        runtimeCommand = "/run/current-system/sw/bin/arbor-openbao-provider";
        providers.local = {
          address = "http://127.0.0.1:8200";
          authMethod = "external";
          tokenFile = "/run/credentials/arbor-vault-token";
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
    machine.wait_for_unit("systemd-vaultd.service")
    machine.wait_for_unit("seed-vaultd-secret.service")
    machine.succeed("systemctl start api.service")
    machine.succeed("test \"$(cat /run/api-credential)\" = 'postgres://runtime.example/db'")
  '';
}
