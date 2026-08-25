{
  pkgs,
  module,
  upstreamModules,
}:
let
  evaluated = pkgs.lib.evalModules {
    modules = [
      {
        config._module.args.pkgs = pkgs;
        options.assertions = pkgs.lib.mkOption { type = pkgs.lib.types.listOf pkgs.lib.types.anything; default = [ ]; };
        options.systemd.services = pkgs.lib.mkOption {
          type = pkgs.lib.types.attrsOf (pkgs.lib.types.submodule { freeformType = pkgs.lib.types.attrsOf pkgs.lib.types.anything; });
          default = { };
        };
        options.systemd.sockets = pkgs.lib.mkOption { type = pkgs.lib.types.attrsOf pkgs.lib.types.anything; default = { }; };
        options.systemd.packages = pkgs.lib.mkOption { type = pkgs.lib.types.listOf pkgs.lib.types.package; default = [ ]; };
        options.services.vault.agents = pkgs.lib.mkOption {
          type = pkgs.lib.types.attrsOf (pkgs.lib.types.submodule {
            options.settings = pkgs.lib.mkOption { type = pkgs.lib.types.attrsOf pkgs.lib.types.anything; default = { }; };
          });
          default = { };
        };
      }
    ] ++ upstreamModules ++ [
      module
      {
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
        systemd.services.api = { };
      }
    ];
  };
  api = evaluated.config.systemd.services.api;
in
assert api.serviceConfig.LoadCredential == [ "db-url:/run/systemd-vaultd/sock" ];
assert api.vault.changeAction == "restart";
assert api.vault.secrets."db-url" != { };
assert api.vault.template != "";
pkgs.emptyFile
