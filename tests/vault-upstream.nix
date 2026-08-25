{
  nixpkgs,
  pkgs,
  system,
  module,
  upstreamModules,
}:
let
  evaluated = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = upstreamModules ++ [
      module
      {
        system.stateVersion = "25.05";
        systemd.services.api = { };
        services.vault.agents.default = { };
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
      }
    ];
  };
  api = evaluated.config.systemd.services.api;
  templates = evaluated.config.services.vault.agents.default.settings.template;
  rendered = builtins.concatStringsSep "\n" (map (template: template.contents or "") templates);
in
assert builtins.elem "db-url:/run/systemd-vaultd/sock" api.serviceConfig.LoadCredential;
assert api.vault.changeAction == "restart";
assert api.vault.secrets."db-url" != { };
assert builtins.match ".*index .Data.data.*url.*" rendered != null;
pkgs.emptyFile
