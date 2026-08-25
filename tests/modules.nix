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
  invalid = evalModules {
    modules = [
      {
        options.assertions = pkgs.lib.mkOption {
          type = pkgs.lib.types.listOf pkgs.lib.types.anything;
          default = [ ];
        };
      }
      module
      {
        cluster.registry.policy.metadata.secret = "public metadata must not contain secrets";
        cluster.vault = {
          requirements = [ "database-read" ];
          bindings.db = {
            requirement = "undeclared";
            service = "/nix/store/not-a-public-service";
          };
        };
      }
    ];
  };
  failedMessages = map (assertion: assertion.message) (
    builtins.filter (assertion: !assertion.assertion) invalid.config.assertions
  );
in
assert valid.config.cluster.registry.policy.metadata.environment == "test";
assert valid.config.cluster.vault.bindings.db.service == "api";
assert pkgs.lib.elem "cluster.vault bindings must refer to declared requirements" failedMessages;
assert pkgs.lib.elem "cluster.vault bindings must name public service identifiers" failedMessages;
assert pkgs.lib.elem "cluster.registry.policy contains a secret-like key or unsafe value"
  failedMessages;
pkgs.emptyFile
