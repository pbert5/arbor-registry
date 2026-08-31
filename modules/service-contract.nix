{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.cluster.registry.runtime;
  tokenInit = pkgs.writeShellScript "arbor-registry-token-init" ''
    if [ ! -s ${lib.escapeShellArg cfg.tokenFile} ]; then
      umask 077
      ${pkgs.coreutils}/bin/head -c 48 /dev/urandom | ${pkgs.coreutils}/bin/base64 -w0 > ${lib.escapeShellArg cfg.tokenFile}
      ${pkgs.coreutils}/bin/chmod 0600 ${lib.escapeShellArg cfg.tokenFile}
    fi
  '';
  readyProbe = pkgs.writeShellScript "arbor-registry-ready" ''
        set -eu
        token=$(${pkgs.coreutils}/bin/cat ${lib.escapeShellArg cfg.tokenFile})
        ${pkgs.python3}/bin/python3 -c '
    import json, socket, sys
    s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(sys.argv[1])
    s.sendall((json.dumps({"operation":"health","token":sys.argv[2]}) + "\n").encode())
    v = json.loads(s.recv(65536)); s.close()
    raise SystemExit(0 if v.get("ok") is True and v.get("status") == "ok" else 1)
    ' ${lib.escapeShellArg cfg.socket} "$token"
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
    users.groups.arbor-registry = { };
    users.users.arbor-registry = {
      isSystemUser = true;
      group = "arbor-registry";
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
      serviceConfig = {
        Type = "simple";
        User = "arbor-registry";
        Group = "arbor-registry";
        StateDirectory = cfg.transportStateDirectory;
        StateDirectoryMode = "0700";
        RuntimeDirectory = [
          "arbor-registry-transport"
          "arbor-registry"
        ];
        Restart = "on-failure";
        RestartSec = 2;
        ExecStartPre = tokenInit;
        ExecStart = "${cfg.transportPackage}/bin/arbor-registry-transport";
        Environment = [
          "ARBOR_REGISTRY_STATE_DIR=/var/lib/${cfg.transportStateDirectory}"
          "ARBOR_REGISTRY_SOCKET=${cfg.transportSocket}"
          "ARBOR_REGISTRY_SOCKET_TOKEN_FILE=${cfg.tokenFile}"
        ];
      };
    };
    systemd.services.arbor-registry = {
      wantedBy = [ "arbor-participant.target" ];
      after = [ "arbor-registry-transport.service" ];
      requires = [ "arbor-registry-transport.service" ];
      serviceConfig = {
        Type = "simple";
        User = "arbor-registry";
        Group = "arbor-registry";
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        RuntimeDirectory = "arbor-registry";
        Restart = "on-failure";
        RestartSec = 2;
        ExecStartPre = tokenInit;
        ExecStart = "${cfg.runtimePackage}/bin/arbor-registryd --config=/etc/arbor-registry/config.json";
        Environment = [ "ARBOR_REGISTRY_CONFIG=/etc/arbor-registry/config.json" ];
      };
    };
    environment.etc."arbor-registry/config.json".text = builtins.toJSON {
      stateDir = "/var/lib/${cfg.stateDirectory}";
      socket = cfg.socket;
      transportSocket = cfg.transportSocket;
      tokenFile = cfg.tokenFile;
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
