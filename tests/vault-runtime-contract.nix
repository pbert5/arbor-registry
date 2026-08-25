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
          nodeIdentityPath = "/var/lib/arbor/node-identity";
          providers.local = {
            address = "bao://local";
            authMethod = "external";
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
assert api.after == [ "systemd-vaultd.service" ];
assert api.wants == [ "systemd-vaultd.service" ];
assert api.serviceConfig.LoadCredential == [ "db-url:/run/arbor-vaultd/credentials/api" ];
assert !(builtins.hasAttr "Environment" api.serviceConfig);
assert !(builtins.hasAttr "EnvironmentFile" api.serviceConfig);
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
