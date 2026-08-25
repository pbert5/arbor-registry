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
  valid = evalModules {
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
  invalid = evalModules {
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
          nodeIdentityPath = "/nix/store/not-runtime";
          providers.local.address = "bao://local";
          requirements.db = {
            provider = "local";
            path = "kv/data/arbor/db";
            field = "url";
            credentialName = "db-url";
          };
        };
      }
    ];
  };
  failed = builtins.filter (assertion: !assertion.assertion) invalid.config.assertions;
  invalidIdentifier = evalModules {
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
          providers.local.address = "bao://local";
          requirements.db = {
            provider = "local";
            path = "kv/data/arbor/db";
            field = "url";
            credentialName = "db-url";
          };
          bindings."api/bad" = {
            requirement = "db";
            service = "api";
          };
        };
      }
    ];
  };
  api = valid.config.systemd.services.api.serviceConfig;
in
assert valid.config.systemd.services.systemd-vaultd != { };
assert api.LoadCredential == [ "db-url:/run/arbor-vaultd/credentials/api" ];
assert api.Restart == "on-failure";
assert valid.config.systemd.services.api.after == [ "systemd-vaultd.service" ];
assert failed != [ ];
assert builtins.any (assertion: !assertion.assertion) invalidIdentifier.config.assertions;
pkgs.emptyFile
