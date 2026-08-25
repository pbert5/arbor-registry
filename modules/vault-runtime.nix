{
  config,
  lib,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.cluster.vault.runtime;

  isUnsafeString =
    value:
    builtins.isString value
    && (
      lib.hasPrefix "/nix/store/" value
      || lib.hasPrefix "/run/secrets/" value
      || lib.hasPrefix "-----BEGIN" value
      || lib.hasInfix "-----BEGIN" value
    );

  isSafeIdentifier =
    value:
    builtins.isString value
    && builtins.stringLength value <= 64
    && builtins.match "[A-Za-z0-9][A-Za-z0-9_-]*" value != null;

  hasUnsafeValue =
    value:
    if builtins.isString value then
      isUnsafeString value
    else if builtins.isList value then
      lib.any hasUnsafeValue value
    else if builtins.isAttrs value then
      lib.any (name: hasUnsafeValue value.${name}) (lib.attrNames value)
    else
      false;

  credentialSource = name: "/run/arbor-vaultd/credentials/${name}";
  requirements = cfg.requirements;
  bindingCredential = name: binding: requirements.${binding.requirement}.credentialName;
  services = lib.mapAttrs' (
    name: binding:
    lib.nameValuePair binding.service {
      after = [ "systemd-vaultd.service" ];
      wants = [ "systemd-vaultd.service" ];
      serviceConfig = {
        LoadCredential = [ "${bindingCredential name binding}:${credentialSource name}" ];
        Restart = "on-failure";
        RestartSec = "5s";
      };
    }
  ) cfg.bindings;
in
{
  # The explicit upstream interface is a module defining
  # `systemd.services.systemd-vaultd`; consumers import that module alongside
  # this one. No daemon implementation or secret fetcher is bundled.
  # Untested runtime procedure: (1) import the pinned upstream module beside
  # this module, (2) provision the node identity at
  # `nodeIdentityPath`, (3) install and configure the provider-side fetcher to
  # write each `/run/arbor-vaultd/credentials/<binding>` file, (4) start the
  # composed systemd-vaultd unit, and (5) verify service restart/reload during
  # a real OpenBao rotation. This contract test performs none of those steps.
  imports = [ ];

  options.cluster.vault.runtime = {
    enable = mkEnableOption "the runtime-only OpenBao/systemd-vaultd boundary";

    nodeIdentityPath = mkOption {
      type = types.str;
      default = "/var/lib/arbor/node-identity";
      description = "Runtime filesystem path for the node identity; never a Nix store path.";
    };

    providers = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            address = mkOption {
              type = types.str;
              description = "Public OpenBao provider address or reference.";
            };
            authMethod = mkOption {
              type = types.enum [
                "approle"
                "kubernetes"
                "unix"
                "external"
              ];
              default = "external";
              description = "Public authentication method implemented by the runtime adapter.";
            };
            namespace = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Optional public OpenBao namespace reference.";
            };
          };
        }
      );
      default = { };
      description = "Public OpenBao provider references, not provider credentials.";
    };

    requirements = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            provider = mkOption {
              type = types.str;
              description = "Provider reference used to resolve this requirement.";
            };
            path = mkOption {
              type = types.str;
              description = "Public OpenBao secret path reference.";
            };
            field = mkOption {
              type = types.str;
              description = "Public field name to request from the referenced secret.";
            };
            credentialName = mkOption {
              type = types.str;
              description = "Systemd credential name exposed to the consuming service.";
            };
          };
        }
      );
      default = { };
      description = "Declarative secret references; values are fetched only at runtime.";
    };

    bindings = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            requirement = mkOption {
              type = types.str;
              description = "Runtime requirement to bind to a service.";
            };
            service = mkOption {
              type = types.str;
              description = "NixOS systemd service receiving the credential.";
            };
          };
        }
      );
      default = { };
      description = "Bindings from runtime requirements to consuming systemd services.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.hasPrefix "/" cfg.nodeIdentityPath && !isUnsafeString cfg.nodeIdentityPath;
        message = "cluster.vault.runtime.nodeIdentityPath must be an absolute runtime path, not a store or secret value";
      }
      {
        assertion = lib.all (
          name:
          cfg.requirements.${name}.provider != ""
          && builtins.hasAttr cfg.requirements.${name}.provider cfg.providers
        ) (lib.attrNames cfg.requirements);
        message = "cluster.vault.runtime requirements must name a declared provider reference";
      }
      {
        assertion = lib.all (
          name:
          cfg.bindings.${name}.requirement != ""
          && builtins.hasAttr cfg.bindings.${name}.requirement cfg.requirements
        ) (lib.attrNames cfg.bindings);
        message = "cluster.vault.runtime bindings must refer to declared requirements";
      }
      {
        assertion = lib.all isSafeIdentifier (lib.attrNames cfg.bindings);
        message = "cluster.vault.runtime binding names must be safe path identifiers (ASCII alphanumeric, '_' or '-')";
      }
      {
        assertion = !hasUnsafeValue cfg;
        message = "cluster.vault.runtime contains a Nix store path or secret value";
      }
    ];

    systemd.services = services;
  };
}
