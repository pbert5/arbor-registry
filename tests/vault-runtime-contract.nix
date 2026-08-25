{ pkgs, module }:
let
  inherit (pkgs.lib) evalModules;
  mockUpstream = {
    options.systemd.services = pkgs.lib.mkOption {
      type = pkgs.lib.types.attrsOf pkgs.lib.types.anything;
      default = { };
    };
    config.systemd.services.systemd-vaultd = {
      description = "mock upstream systemd-vaultd";
    };
  };
  evaluated = evalModules {
    modules = [
      {
        options.assertions = pkgs.lib.mkOption {
          type = pkgs.lib.types.listOf pkgs.lib.types.anything;
          default = [ ];
        };
      }
      mockUpstream
      module
      {
        cluster.vault.runtime = {
          enable = true;
          runtimeCommand = "/run/current-system/sw/bin/arbor-openbao-provider";
          nodeIdentityPath = "/var/lib/arbor/node-identity";
          providers.local = {
            address = "http://127.0.0.1:8200";
            authMethod = "external";
            tokenFile = "/run/credentials/arbor-vault-token";
          };
          requirements.db = {
            provider = "local";
            path = "kv/data/arbor/db";
            field = "url";
            credentialName = "db-url";
          };
          bindings.api = {
            requirement = "db";
            service = "api";
          };
        };
      }
    ];
  };
  api = evaluated.config.systemd.services.api;
in
assert evaluated.config.systemd.services.systemd-vaultd != { };
assert api.after == [ "arbor-vault-runtime-api-init.service" ];
assert api.wants == [ "arbor-vault-runtime-api-init.service" ];
assert api.serviceConfig.LoadCredential == [ "db-url:/run/arbor-vaultd/credentials/api" ];
assert !(builtins.hasAttr "Environment" api.serviceConfig);
assert !(builtins.hasAttr "EnvironmentFile" api.serviceConfig);
assert
  evaluated.config.systemd.services.arbor-vault-runtime-api.serviceConfig.RuntimeDirectory
  == "arbor-vaultd";
pkgs.runCommand "arbor-registry-vault-runtime-contract"
  {
    nativeBuildInputs = [
      pkgs.bash
      pkgs.coreutils
    ];
  }
  ''
    ${pkgs.bash}/bin/bash ${./vault-runtime-contract.sh}
    touch $out
  ''
