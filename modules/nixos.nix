{ config, lib, ... }:
let
  inherit (lib)
    mkEnableOption
    mkOption
    types
    ;
  publicScalar = types.oneOf [
    types.bool
    types.int
    types.str
  ];
  publicMetadata = types.attrsOf (types.either publicScalar (types.listOf publicScalar));
  unsafeNames = [
    "secret"
    "password"
    "passphrase"
    "token"
    "credential"
    "privatekey"
    "private-key"
    "signingkey"
    "signing-key"
    "apikey"
    "accesskey"
    "accesstoken"
    "access-token"
    "seed"
  ];
  hasUnsafeName = name:
    let normalized = lib.toLower (builtins.replaceStrings [ "_" ] [ "" ] name);
    in lib.elem normalized unsafeNames;
  hasUnsafeValue =
    value:
    if builtins.isString value then
      lib.hasPrefix "/nix/store/" value
      || lib.hasPrefix "/run/secrets/" value
      || lib.hasPrefix "-----BEGIN" value
    else if builtins.isList value then
      lib.any hasUnsafeValue value
    else if builtins.isAttrs value then
      lib.any (name: hasUnsafeName name || hasUnsafeValue value.${name}) (lib.attrNames value)
    else
      false;
  bindingsHaveDeclaredRequirements = lib.all (
    binding: lib.elem binding.requirement config.cluster.vault.requirements
  ) (lib.attrValues config.cluster.vault.bindings);
  bindingsHavePublicServices = lib.all (
    binding: binding.service != "" && !hasUnsafeValue binding.service
  ) (lib.attrValues config.cluster.vault.bindings);
in
{
  options.cluster.registry = {
    enable = mkEnableOption "the declarative Arbor registry policy boundary";

    policy = mkOption {
      type = types.submodule {
        options = {
          protocolEpoch = mkOption {
            type = types.ints.positive;
            default = 1;
            description = "Accepted registry protocol epoch.";
          };
          allowedIssuers = mkOption {
            type = types.listOf types.str;
            default = [ ];
            description = "Public issuer identifiers permitted by policy.";
          };
          requiredFeatures = mkOption {
            type = types.listOf types.str;
            default = [ ];
            description = "Public features required of registry records.";
          };
          maxRecordBytes = mkOption {
            type = types.ints.positive;
            default = 131072;
            description = "Maximum public registry record size.";
          };
          metadata = mkOption {
            type = publicMetadata;
            default = { };
            description = "Non-secret public policy metadata.";
          };
        };
      };
      default = { };
      description = "Public registry acceptance policy; it does not contain credentials.";
    };

    bootstrap = mkOption {
      type = types.submodule {
        options = {
          peers = mkOption {
            type = types.listOf types.str;
            default = [ ];
            description = "Public peer identifiers used for bootstrap metadata.";
          };
          endpoints = mkOption {
            type = types.listOf types.str;
            default = [ ];
            description = "Public, network-neutral endpoint identifiers.";
          };
          metadata = mkOption {
            type = publicMetadata;
            default = { };
            description = "Non-secret bootstrap metadata.";
          };
        };
      };
      default = { };
      description = "Public bootstrap metadata only; no live network configuration.";
    };
  };

  options.cluster.vault = {
    requirements = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Names of public vault capabilities required by services.";
    };
    bindings = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            requirement = mkOption {
              type = types.str;
              description = "Requirement name this binding refers to.";
            };
            service = mkOption {
              type = types.str;
              description = "Public service identifier receiving the capability.";
            };
          };
        }
      );
      default = { };
      description = "Public requirement-to-service bindings, never secret material.";
    };
  };

  config = {
    assertions = [
      {
        assertion = !hasUnsafeValue config.cluster.vault;
        message = "cluster.vault contains a secret-like key or unsafe value";
      }
      {
        assertion = bindingsHaveDeclaredRequirements;
        message = "cluster.vault bindings must refer to declared requirements";
      }
      {
        assertion = bindingsHavePublicServices;
        message = "cluster.vault bindings must name public service identifiers";
      }
      {
        assertion = !hasUnsafeValue config.cluster.registry.policy;
        message = "cluster.registry.policy contains a secret-like key or unsafe value";
      }
      {
        assertion = !hasUnsafeValue config.cluster.registry.bootstrap;
        message = "cluster.registry.bootstrap contains a secret-like key or unsafe value";
      }
    ];
  };
}
