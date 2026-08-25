{
  pkgs,
  systemd-vaultd,
  arborVaultRuntimeModule,
  arborVaultRuntimeSystemdVaultdModule,
}:
let
  openbaoCompat = pkgs.runCommand "arbor-openbao-vault-compat" { } ''
    mkdir -p $out/bin
    ln -s ${pkgs.lib.getExe pkgs.openbao} $out/bin/vault
    ln -s ${pkgs.lib.getExe pkgs.openbao} $out/bin/bao
  '';
in
pkgs.testers.runNixOSTest {
  name = "arbor-registry-vault-runtime-openbao";

  nodes.machine =
    { config, ... }:
    {
      imports = [
        systemd-vaultd.nixosModules.vaultAgent
        systemd-vaultd.nixosModules.systemdVaultd
        arborVaultRuntimeModule
        arborVaultRuntimeSystemdVaultdModule
      ];

      environment.systemPackages = [ openbaoCompat ];
      services.vault = {
        enable = true;
        package = openbaoCompat;
        dev = true;
      };

      systemd.services.setup-arbor-openbao = {
        wantedBy = [ "multi-user.target" ];
        after = [ "vault.service" ];
        wants = [ "vault.service" ];
        path = [
          pkgs.coreutils
          pkgs.gnugrep
          pkgs.jq
          openbaoCompat
        ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          RuntimeDirectory = "arbor-openbao-test";
        };
        script = ''
          set -euo pipefail
          until vault status >/dev/null 2>&1; do sleep 1; done
          root_token=$(journalctl -u vault.service --no-pager | sed -n 's/.*Root Token: //p' | tail -n 1)
          test -n "$root_token"
          install -m 0600 /dev/null /run/arbor-openbao-test/root.token
          printf '%s' "$root_token" >/run/arbor-openbao-test/root.token
          export HOME=/run/arbor-openbao-test/home
          install -d -m 0700 "$HOME"
          vault login "$(cat /run/arbor-openbao-test/root.token)" >/dev/null
          secret="arbor-runtime-$(od -An -N8 -tu8 /dev/urandom | tr -d ' ')"
          printf '%s' "$secret" >/run/arbor-openbao-test/expected
          vault kv put secret/arbor-runtime db_url="$secret" >/dev/null
          vault auth enable approle >/dev/null
          vault policy write arbor-runtime - <<'EOF'
          path "secret/data/arbor-runtime" {
            capabilities = ["read"]
          }
          EOF
          vault write auth/approle/role/arbor-runtime token_policies=arbor-runtime >/dev/null
          vault read -format=json auth/approle/role/arbor-runtime/role-id | jq -r .data.role_id >/run/arbor-openbao-test/role-id
          vault write -format=json -force auth/approle/role/arbor-runtime/secret-id | jq -r .data.secret_id >/run/arbor-openbao-test/secret-id
          chmod 0600 /run/arbor-openbao-test/role-id /run/arbor-openbao-test/secret-id
        '';
      };

      services.vault.agents.default = {
        package = pkgs.openbao;
        settings = {
          vault.address = "http://127.0.0.1:8200";
          auto_auth.method = [
            {
              type = "approle";
              config = {
                role_id_file_path = "/run/arbor-openbao-test/role-id";
                secret_id_file_path = "/run/arbor-openbao-test/secret-id";
              };
            }
          ];
        };
      };

      systemd.services.setup-arbor-openbao.before = [ "vault-agent-default.service" ];
      systemd.services.vault-agent-default.after = [ "setup-arbor-openbao.service" ];
      systemd.services.vault-agent-default.wants = [ "setup-arbor-openbao.service" ];

      cluster.vault.runtime = {
        enable = true;
        providers.local.address = "bao://local";
        requirements.db = {
          provider = "local";
          path = "secret/data/arbor-runtime";
          field = "db_url";
          credentialName = "db-url";
        };
        bindings.api = {
          requirement = "db";
          service = "api";
        };
      };

      systemd.services.api = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          cat "$CREDENTIALS_DIRECTORY/db-url" >/run/arbor-openbao-test/observed
          sleep infinity
        '';
      };
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("vault.service")
    machine.wait_for_unit("setup-arbor-openbao.service")
    machine.wait_for_unit("vault-agent-default.service")
    machine.wait_for_unit("api.service")
    machine.succeed("test \"$(cat /run/arbor-openbao-test/observed)\" = \"$(cat /run/arbor-openbao-test/expected)\"")
    machine.succeed("test -z \"$(systemctl show --value --property Environment api.service)\"")
    machine.succeed("test -z \"$(systemctl show --value --property EnvironmentFile api.service)\"")
    machine.succeed("! tr '\\0' '\\n' </proc/$(systemctl show --value --property MainPID api.service)/environ | grep -F \"$(cat /run/arbor-openbao-test/expected)\"")
    machine.succeed("! grep -R -F \"$(cat /run/arbor-openbao-test/expected)\" /nix/store")

    machine.succeed("export HOME=/run/arbor-openbao-test/home; vault kv put secret/arbor-runtime db_url=arbor-runtime-rotated >/dev/null")
    machine.wait_until_succeeds("test \"$(cat /run/arbor-openbao-test/observed)\" = arbor-runtime-rotated")
  '';
}
