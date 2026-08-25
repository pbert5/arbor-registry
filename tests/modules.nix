{ pkgs, module }:
let
  inherit (pkgs.lib) evalModules;
  valid = evalModules {
    modules = [
      {
        options.assertions = pkgs.lib.mkOption {
          type = pkgs.lib.types.listOf pkgs.lib.types.anything;
          default = [ ];
        };
      }
      module
      {
        cluster.registry.enable = true;
        cluster.registry.policy.metadata = {
          environment = "test";
          quorum = 2;
        };
        cluster.registry.bootstrap = {
          peers = [ "peer-a" ];
          endpoints = [ "endpoint-a" ];
        };
        cluster.vault = {
          requirements = [ "database-read" ];
          bindings.db = {
            requirement = "database-read";
            service = "api";
          };
        };
      }
    ];
  };
in
assert valid.config.cluster.registry.policy.metadata.environment == "test";
assert valid.config.cluster.vault.bindings.db.service == "api";
pkgs.emptyFile
