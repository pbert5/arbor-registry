{
  config,
  lib,
  ...
}:
let
  cfg = config.cluster.vault.runtime;
  requirements = cfg.requirements;

  templateFor =
    service: bindings:
    let
      entries = lib.concatMapStringsSep "," (
        bindingName:
        let
          binding = bindings.${bindingName};
          requirement = requirements.${binding.requirement};
        in
        builtins.toJSON requirement.credentialName
        + ":{{ with secret \""
        + requirement.path
        + "\" }}{{ index .Data.data \""
        + requirement.field
        + "\" | toJSON }}{{ end }}"
      ) (lib.attrNames bindings);
    in
    "{" + entries + "}";

  bindingsByService = lib.foldlAttrs (
    acc: bindingName: binding:
    acc
    // {
      ${binding.service} = (acc.${binding.service} or { }) // {
        ${bindingName} = binding;
      };
    }
  ) { } cfg.bindings;

  services = lib.mapAttrs (service: bindings: {
    vault = {
      template = templateFor service bindings;
      secrets = lib.mapAttrs' (
        _bindingName: binding: lib.nameValuePair requirements.${binding.requirement}.credentialName { }
      ) bindings;
      changeAction = "restart";
    };
  }) bindingsByService;
in
{
  # This adapter targets numtide/systemd-vaultd's public NixOS module API.
  # The upstream vault-agent module renders this template at runtime; only
  # public paths, fields, and credential names enter the Nix configuration.
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (
          name:
          let
            requirement = requirements.${name};
          in
          builtins.match "[A-Za-z0-9_./-]+" requirement.path != null
          && builtins.match "[A-Za-z0-9_ -]+" requirement.field != null
        ) (lib.attrNames requirements);
        message = "cluster.vault.runtime OpenBao paths and fields must be public template identifiers";
      }
    ];
    systemd.services = services;
  };
}
