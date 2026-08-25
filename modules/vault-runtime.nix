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
      || builtins.match "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#[:space:]]+:[^/?#[:space:]]+@.*$" value != null
      || builtins.match "^Bearer[[:space:]]+[^[:space:]]+$" value != null
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
  providerArgs =
    provider: requirement: bindingName: service:
    [
      cfg.runtimeCommand
      "--path"
      requirement.path
      "--field"
      requirement.field
      "--output"
      (credentialSource bindingName)
      "--ready"
      "/run/arbor-vaultd/ready/${bindingName}"
    ]
    ++ lib.optionals (provider.command != null) ([ "--provider-command" ] ++ provider.command)
    ++ lib.optionals (provider.command == null) [
      "--address"
      provider.address
    ]
    ++ lib.optionals (provider.namespace != null) [
      "--namespace"
      provider.namespace
    ]
    ++ lib.optionals (provider.tokenFile != null) [
      "--token-file"
      provider.tokenFile
    ]
    ++ [
      "--watch"
      "--interval"
      (toString cfg.refreshInterval)
      "--restart-command"
      "/run/current-system/sw/bin/systemctl"
      "try-restart"
      service
    ];
  services = lib.mapAttrs' (
    name: binding:
    let
      fetcher = "arbor-vault-runtime-${name}";
    in
    lib.nameValuePair binding.service {
      after = [ "${fetcher}.service" ];
      wants = [ "${fetcher}.service" ];
      serviceConfig = {
        LoadCredential = [ "${bindingCredential name binding}:${credentialSource name}" ];
        Restart = "on-failure";
        RestartSec = "5s";
      };
    }
  ) cfg.bindings;
  fetcherServices = lib.mapAttrs' (
    name: binding:
    let
      requirement = requirements.${binding.requirement};
      provider = cfg.providers.${requirement.provider};
      fetcher = "arbor-vault-runtime-${name}";
    in
    lib.nameValuePair fetcher {
      description = "Runtime OpenBao credential fetch (${name})";
      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-vaultd.service" ];
      wants = [ "systemd-vaultd.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = lib.escapeShellArgs (providerArgs provider requirement name binding.service);
        Restart = "on-failure";
        RestartSec = "5s";
        RuntimeDirectory = "arbor-vaultd";
        RuntimeDirectoryMode = "0700";
      };
    }
  ) cfg.bindings;
in
{
  # The explicit upstream interface is a module defining
  # `systemd.services.systemd-vaultd`; consumers import that module alongside
  # this one. Fetchers remain runtime-only and never receive secret values from
  # Nix evaluation; they consume either a command or a token file at runtime.
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
              type = types.nullOr types.str;
              default = null;
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
            command = mkOption {
              type = types.nullOr (types.listOf types.str);
              default = null;
              description = "Runtime command reading a JSON request on stdin and returning an OpenBao-shaped JSON response.";
            };
            tokenFile = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Runtime-only file containing the OpenBao token; never a Nix secret value.";
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

    runtimeCommand = mkOption {
      type = types.str;
      default = "/run/current-system/sw/bin/arbor-openbao-provider";
      description = "Absolute runtime path to arbor-openbao-provider.";
    };

    refreshInterval = mkOption {
      type = types.ints.positive;
      default = 30;
      description = "Seconds between runtime provider reads for rotation detection.";
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
          let
            provider = cfg.providers.${name};
          in
          provider.command != null || provider.address != null
        ) (lib.attrNames cfg.providers);
        message = "cluster.vault.runtime providers must define either command or address";
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
        assertion =
          !hasUnsafeValue (builtins.removeAttrs cfg [ "providers" ])
          && lib.all (
            name:
            let
              provider = cfg.providers.${name};
              commandArgs = if provider.command == null then [ ] else provider.command;
            in
            (provider.address == null || !isUnsafeString provider.address)
            && (provider.namespace == null || !isUnsafeString provider.namespace)
            && (
              provider.tokenFile == null
              || (lib.hasPrefix "/" provider.tokenFile && !isUnsafeString provider.tokenFile)
            )
            && lib.all (
              value: !(lib.hasPrefix "-----BEGIN" value) && !(lib.hasPrefix "/run/secrets/" value)
            ) commandArgs
          ) (lib.attrNames cfg.providers);
        message = "cluster.vault.runtime contains a Nix store path or secret value";
      }
    ];

    systemd.services = services // fetcherServices;
  };
}
