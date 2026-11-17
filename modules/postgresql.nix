{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.cluster.registry.postgresql;
  pgService = pkgs.writeText "arbor-pg-service.conf" "[arbor-registry-readonly]\nhost=/run/postgresql\nport=${toString config.services.postgresql.settings.port}\ndbname=arbor_registry\nuser=arbor_registry_readonly\n";
  servers = pkgs.writeText "arbor-pgadmin-servers.json" (
    builtins.toJSON {
      Servers."1" = {
        Name = "Local Arbor Registry (read only)";
        Group = "Arbor";
        Host = "/run/postgresql";
        Port = config.services.postgresql.settings.port;
        MaintenanceDB = "arbor_registry";
        Username = "arbor_registry_readonly";
        Service = "arbor-registry-readonly";
        SSLMode = "prefer";
      };
    }
  );
in
{
  options.cluster.registry.postgresql = {
    enable = lib.mkEnableOption "local PostgreSQL storage for the registry";
    pgadmin = {
      enable = lib.mkEnableOption "loopback pgAdmin for the local registry";
      initialEmail = lib.mkOption {
        type = lib.types.str;
        default = "admin@example.com";
      };
      initialPasswordFile = lib.mkOption {
        type = lib.types.str;
        description = "Absolute runtime path to the initial pgAdmin login password file.";
      };
      port = lib.mkOption {
        type = lib.types.port;
        default = 5050;
      };
    };
  };
  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = config.cluster.registry.runtime.enable;
          message = "Registry PostgreSQL requires cluster.registry.runtime.enable.";
        }
      ];
      services.postgresql = {
        enable = true;
        ensureDatabases = [ "arbor_registry" ];
        ensureUsers = [
          {
            name = "arbor-registry";
            ensureDBOwnership = false;
          }
          { name = "arbor_registry_readonly"; }
        ];
        authentication = lib.mkBefore ''
          local arbor_registry arbor_registry_readonly peer map=arbor-pgadmin
        '';
        identMap = lib.mkBefore ''
          arbor-pgadmin pgadmin arbor_registry_readonly
        '';
      };
      systemd.services.arbor-registry-postgresql-setup = {
        description = "Provision Arbor Registry PostgreSQL privileges";
        requires = [
          "postgresql.service"
          "postgresql-setup.service"
        ];
        after = [
          "postgresql.service"
          "postgresql-setup.service"
        ];
        before = [
          "arbor-registry.service"
          "pgadmin.service"
        ];
        environment.PGPORT = toString config.services.postgresql.settings.port;
        serviceConfig = {
          Type = "oneshot";
          User = "postgres";
          RemainAfterExit = true;
        };
        script = ''
          ${config.services.postgresql.package}/bin/psql -v ON_ERROR_STOP=1 -d postgres -c 'ALTER DATABASE arbor_registry OWNER TO "arbor-registry"'
          ${config.services.postgresql.package}/bin/psql -v ON_ERROR_STOP=1 -d arbor_registry <<'SQL'
          REVOKE ALL ON DATABASE arbor_registry FROM PUBLIC;
          GRANT CONNECT ON DATABASE arbor_registry TO arbor_registry_readonly;
          REVOKE CREATE ON SCHEMA public FROM PUBLIC;
          GRANT USAGE ON SCHEMA public TO arbor_registry_readonly;
          GRANT SELECT ON ALL TABLES IN SCHEMA public TO arbor_registry_readonly;
          ALTER DEFAULT PRIVILEGES FOR ROLE "arbor-registry" IN SCHEMA public GRANT SELECT ON TABLES TO arbor_registry_readonly;
          SQL
        '';
      };
      systemd.services.arbor-registry = {
        requires = [ "arbor-registry-postgresql-setup.service" ];
        after = [ "arbor-registry-postgresql-setup.service" ];
        partOf = [ "postgresql.service" ];
        environment = {
          PGDATABASE = "arbor_registry";
          PGUSER = "arbor-registry";
          PGHOST = "/run/postgresql";
          PGPORT = toString config.services.postgresql.settings.port;
        };
      };
    })
    (lib.mkIf cfg.pgadmin.enable {
      assertions = [
        {
          assertion = cfg.enable;
          message = "Registry pgAdmin requires cluster.registry.postgresql.enable.";
        }
        {
          assertion =
            lib.hasPrefix "/" cfg.pgadmin.initialPasswordFile
            && !(lib.hasPrefix "/nix/store/" cfg.pgadmin.initialPasswordFile);
          message = "pgAdmin password must be an absolute runtime path outside the Nix store.";
        }
      ];
      services.pgadmin = {
        enable = true;
        inherit (cfg.pgadmin) initialEmail initialPasswordFile port;
        settings.DEFAULT_SERVER = "127.0.0.1";
        openFirewall = false;
      };
      systemd.services.pgadmin = {
        environment.PGSERVICEFILE = pgService;
        requires = [ "arbor-registry-postgresql-setup.service" ];
        after = [ "arbor-registry-postgresql-setup.service" ];
        preStart = lib.mkAfter ''
          if [ ! -e /var/lib/pgadmin/arbor-servers-loaded ]; then
            ${config.services.pgadmin.package}/bin/pgadmin4-cli load-servers ${servers} --user ${lib.escapeShellArg cfg.pgadmin.initialEmail}
            dump=$(${pkgs.coreutils}/bin/mktemp)
            trap 'rm -f "$dump"' EXIT
            ${config.services.pgadmin.package}/bin/pgadmin4-cli dump-servers "$dump" --user ${lib.escapeShellArg cfg.pgadmin.initialEmail}
            ${pkgs.jq}/bin/jq -e '.Servers | any(.[]; .Name == "Local Arbor Registry (read only)")' "$dump" >/dev/null
            touch /var/lib/pgadmin/arbor-servers-loaded
          fi
        '';
      };
    })
  ];
}
