{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.cluster.registry.runtime;
  validStateDirectory =
    name:
    builtins.match "[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*" name != null
    && lib.all (part: part != "." && part != "..") (lib.splitString "/" name);
  separateStateDirectories =
    cfg.stateDirectory != cfg.transportStateDirectory
    && !(lib.hasPrefix "${cfg.stateDirectory}/" cfg.transportStateDirectory)
    && !(lib.hasPrefix "${cfg.transportStateDirectory}/" cfg.stateDirectory);
  trustedAncestors = ''
    cursor="$parent"
    while :; do
      owner=$(${pkgs.coreutils}/bin/stat -c %u "$cursor")
      [ "$owner" = 0 ] || [ "$owner" = "$EUID" ]
      [ -z "$(${pkgs.findutils}/bin/find "$cursor" -maxdepth 0 -perm /022 -print)" ]
      [ "$cursor" = / ] && break
      cursor=$(${pkgs.coreutils}/bin/dirname "$cursor")
    done
  '';
  tokenInit = pkgs.writeShellScript "arbor-registry-token-init" ''
    set -eu
    token=${lib.escapeShellArg cfg.tokenFile}
    parent=$(${pkgs.coreutils}/bin/dirname "$token")
    [ "$(${pkgs.coreutils}/bin/realpath -e "$parent")" = "$parent" ]
    [ -d "$parent" ] && [ -O "$parent" ]
    ${trustedAncestors}
    if [ -L "$token" ]; then exit 1; fi
    created=0
    if [ ! -e "$token" ]; then
      umask 077
      ${pkgs.coreutils}/bin/head -c 48 /dev/urandom | ${pkgs.coreutils}/bin/base64 -w0 > "$token"
      created=1
    fi
    [ -f "$token" ] && [ -O "$token" ] && [ -s "$token" ]
    # Only migrate the known default token; do not broaden an arbitrary existing file.
    if [ "$created" = 1 ] || [ "$token" = /run/arbor-registry/socket-token ]; then
      ${pkgs.coreutils}/bin/chgrp arbor-registry "$token"
      ${pkgs.coreutils}/bin/chmod 0640 "$token"
    else
      [ "$(${pkgs.coreutils}/bin/stat -c '%G:%a' "$token")" = arbor-registry:640 ]
    fi
  '';
  socketParentCheck =
    socket:
    pkgs.writeShellScript "arbor-registry-socket-parent-check" ''
      set -eu
      parent=$(${pkgs.coreutils}/bin/dirname ${lib.escapeShellArg socket})
      [ "$(${pkgs.coreutils}/bin/realpath -e "$parent")" = "$parent" ]
      [ -d "$parent" ] && [ -O "$parent" ]
      ${trustedAncestors}
    '';
  readyProbe = pkgs.writeShellScript "arbor-registry-ready" ''
        set -eu
        ${pkgs.python3}/bin/python3 -c '
    import json, socket, sys
    s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(sys.argv[1])
    s.sendall((json.dumps({"operation":"health","token":open(sys.argv[2]).read().strip()}) + "\n").encode())
    v = json.loads(s.recv(65536)); s.close()
    raise SystemExit(0 if v.get("ok") is True and v.get("status") == "ok" else 1)
    ' ${lib.escapeShellArg cfg.socket} ${lib.escapeShellArg cfg.tokenFile}
  '';
  serviceState = name: ''
    enabled=0; running=0
    ${pkgs.systemd}/bin/systemctl is-enabled --quiet ${lib.escapeShellArg name} && enabled=1 || true
    ${pkgs.systemd}/bin/systemctl is-active --quiet ${lib.escapeShellArg name} && running=1 || true
    printf '{"enabled":%s,"running":%s}' "$enabled" "$running"
  '';
  statusScript = pkgs.writeShellScript "arbor-runtime-status" ''
    set -eu
    out=${lib.escapeShellArg cfg.statusPath}; tmp="$out.tmp.$$"
    install -d -m 0755 "$(dirname "$out")"
    registry=$(${serviceState cfg.registryService})
    transport=$(${serviceState cfg.transportService})
    ready=0; ${pkgs.coreutils}/bin/timeout 2s ${lib.escapeShellArg readyProbe} >/dev/null 2>&1 && ready=1 || true
    ri=false; ti=false; [ -x ${lib.escapeShellArg "${cfg.runtimePackage}/bin/arbor-registryd"} ] && ri=true || true
    [ -x ${lib.escapeShellArg "${cfg.transportPackage}/bin/arbor-registry-transport"} ] && ti=true || true
    ${pkgs.jq}/bin/jq -n --argjson registry "$registry" --argjson transport "$transport" --argjson ready "$ready" --argjson ri "$ri" --argjson ti "$ti" \
      '{version:1,generatedAt:(now|floor),status:(if ($ri and $ti and ($registry.enabled == 1) and ($registry.running == 1) and ($transport.enabled == 1) and ($transport.running == 1) and ($ready == 1)) then "healthy" else "degraded" end),healthy:($ri and $ti and ($registry.enabled == 1) and ($registry.running == 1) and ($transport.enabled == 1) and ($transport.running == 1) and ($ready == 1)),ready:($ri and ($registry.enabled == 1) and ($registry.running == 1) and ($ready == 1)),reason:(if ($ri|not) then "registry unavailable" elif ($registry.running != 1) then "registry unavailable" elif ($ready != 1) then "registry unavailable" elif ($ti|not) or ($transport.running != 1) then "transport unavailable" else null end),registry:($registry + {installed:$ri,ready:($ready == 1)}),transport:($transport + {installed:$ti}),provider:{installed:false,authenticated:false},vaultd:{installed:false,running:false},openbao:{installed:false,initialized:null,sealed:null}}' > "$tmp"
    chmod 0644 "$tmp"; mv -f "$tmp" "$out"
  '';
in
{
  options.cluster.registry.runtime = {
    enable = lib.mkEnableOption "the Arbor participant runtime";
    registryService = lib.mkOption {
      type = lib.types.str;
      default = "arbor-registry.service";
    };
    transportService = lib.mkOption {
      type = lib.types.str;
      default = "arbor-registry-transport.service";
    };
    statusPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/arbor/doctor/status.json";
    };
    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "arbor-registry";
    };
    transportStateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "arbor-registry-transport";
    };
    socket = lib.mkOption {
      type = lib.types.str;
      default = "/run/arbor-registry/registry.sock";
    };
    transportSocket = lib.mkOption {
      type = lib.types.str;
      default = "/run/arbor-registry-transport/transport.sock";
    };
    transportRealmId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Shared public transport realm identifier for isolated integration tests.";
    };
    transportProtocolEpoch = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
    };
    transportListen = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
    transportBootstrapPeers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
    transportDatabaseAddresses = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
    };
    bootstrapAuthoritiesFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/arbor-registry/bootstrap-authorities.json";
    };
    authorityIssuers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
    syncInterval = lib.mkOption {
      type = lib.types.ints.positive;
      default = 5;
      description = "Seconds between automatic bounded registry consumer runs.";
    };
    syncMaxBackoff = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "Maximum seconds between retries after a provider outage.";
    };
    syncMaxPages = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4;
      description = "Maximum provider pages consumed by one automatic run.";
    };
    syncPageSize = lib.mkOption {
      type = lib.types.ints.positive;
      default = 100;
      description = "Maximum records fetched in one automatic provider page.";
    };
    tokenFile = lib.mkOption {
      type = lib.types.str;
      default = "/run/arbor-registry/socket-token";
    };
    runtimePackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../runtime/package.nix { };
    };
    transportPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../transport/package.nix { };
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          validStateDirectory cfg.stateDirectory
          && validStateDirectory cfg.transportStateDirectory
          && separateStateDirectories;
        message = "Registry and transport state directories must be valid, distinct, and non-overlapping";
      }
    ];
    users.groups.arbor-registry = { };
    users.users.arbor-registry = {
      isSystemUser = true;
      group = "arbor-registry";
    };
    users.users.arbor-registry-transport = {
      isSystemUser = true;
      group = "arbor-registry";
    };
    systemd.services.arbor-registry-token = {
      serviceConfig = {
        Type = "oneshot";
        User = "arbor-registry";
        Group = "arbor-registry";
        RuntimeDirectory = "arbor-registry";
        RuntimeDirectoryMode = "0750";
        RuntimeDirectoryPreserve = true;
        RemainAfterExit = true;
        ExecStart = tokenInit;
      };
    };
    systemd.targets.arbor-participant = {
      description = "Arbor participant runtime services";
      wantedBy = [ "multi-user.target" ];
      wants = [
        "arbor-registry.service"
        "arbor-registry-transport.service"
      ];
    };
    systemd.services.arbor-registry-transport = {
      wantedBy = [ "arbor-participant.target" ];
      after = [ "arbor-registry-token.service" ];
      requires = [ "arbor-registry-token.service" ];
      serviceConfig = {
        Type = "simple";
        User = "arbor-registry-transport";
        Group = "arbor-registry";
        StateDirectory = cfg.transportStateDirectory;
        StateDirectoryMode = "0700";
        RuntimeDirectory = "arbor-registry-transport";
        RuntimeDirectoryMode = "0750";
        # The token service preserves the shared runtime directory across stops.
        RuntimeDirectoryPreserve = true;
        Restart = "on-failure";
        RestartSec = 2;
        ExecStartPre = socketParentCheck cfg.transportSocket;
        ExecStart = "${cfg.transportPackage}/bin/arbor-registry-transport";
        Environment = [
          "ARBOR_REGISTRY_STATE_DIR=/var/lib/${cfg.transportStateDirectory}"
          "ARBOR_REGISTRY_SOCKET=${cfg.transportSocket}"
          "ARBOR_REGISTRY_SOCKET_TOKEN_FILE=${cfg.tokenFile}"
          "ARBOR_REGISTRY_REALM_ID=${lib.optionalString (cfg.transportRealmId != null) cfg.transportRealmId}"
          "ARBOR_REGISTRY_PROTOCOL_EPOCH=${toString cfg.transportProtocolEpoch}"
          "ARBOR_REGISTRY_LISTEN=${lib.concatStringsSep "," cfg.transportListen}"
          "ARBOR_REGISTRY_BOOTSTRAP_PEERS=${lib.concatStringsSep "," cfg.transportBootstrapPeers}"
          "ARBOR_REGISTRY_DATABASE_ADDRESSES=${builtins.toJSON cfg.transportDatabaseAddresses}"
        ];
      };
    };
    systemd.services.arbor-registry = {
      wantedBy = [ "arbor-participant.target" ];
      after = [
        "arbor-registry-token.service"
        "arbor-registry-transport.service"
      ];
      requires = [
        "arbor-registry-token.service"
        "arbor-registry-transport.service"
      ];
      serviceConfig = {
        Type = "simple";
        User = "arbor-registry";
        Group = "arbor-registry";
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        RuntimeDirectory = "arbor-registry";
        RuntimeDirectoryMode = "0750";
        RuntimeDirectoryPreserve = true;
        Restart = "on-failure";
        RestartSec = 2;
        ExecStartPre = socketParentCheck cfg.socket;
        ExecStart = "${cfg.runtimePackage}/bin/arbor-registryd --config=/etc/arbor-registry/config.json";
        Environment = [ "ARBOR_REGISTRY_CONFIG=/etc/arbor-registry/config.json" ];
      };
    };
    environment.etc."arbor-registry/config.json".text = builtins.toJSON {
      stateDir = "/var/lib/${cfg.stateDirectory}";
      socket = cfg.socket;
      transportSocket = cfg.transportSocket;
      tokenFile = cfg.tokenFile;
      bootstrapAuthoritiesFile = cfg.bootstrapAuthoritiesFile;
      authorityIssuers = cfg.authorityIssuers;
      syncInterval = cfg.syncInterval;
      syncMaxBackoff = cfg.syncMaxBackoff;
      syncMaxPages = cfg.syncMaxPages;
      syncPageSize = cfg.syncPageSize;
    };
    systemd.services.arbor-runtime-status = {
      wantedBy = [ "arbor-participant.target" ];
      after = [
        "arbor-registry.service"
        "arbor-registry-transport.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = statusScript;
      };
    };
    systemd.timers.arbor-runtime-status = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "10s";
        OnUnitActiveSec = "30s";
        Unit = "arbor-runtime-status.service";
      };
    };
  };
}
