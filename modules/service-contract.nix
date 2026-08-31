{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.cluster.registry.runtime;
  serviceState = name: ''
    enabled=0; running=0
    ${pkgs.systemd}/bin/systemctl is-enabled --quiet ${lib.escapeShellArg name} && enabled=1 || true
    ${pkgs.systemd}/bin/systemctl is-active --quiet ${lib.escapeShellArg name} && running=1 || true
    printf '{"enabled":%s,"running":%s}' "$enabled" "$running"
  '';
  statusScript = pkgs.writeShellScript "arbor-runtime-status" ''
    set -eu
    out=${lib.escapeShellArg cfg.statusPath}
    tmp="$out.tmp.$$"
    rm -f "$out"
    install -d -m 0755 "$(dirname "$out")"
    registry=$(${serviceState cfg.registryService})
    transport=$(${serviceState cfg.transportService})
    vaultd=$(${serviceState cfg.vaultdService})
    generated_at=$(${pkgs.coreutils}/bin/date +%s)
    registry_ready=0
    if [ -n ${lib.escapeShellArg cfg.registryReadyCommand} ]; then
      ${pkgs.coreutils}/bin/timeout 2s ${lib.escapeShellArg cfg.registryReadyCommand} >/dev/null 2>&1 && registry_ready=1 || true
    fi
    provider=0
    provider_state='{"enabled":0,"running":0}'
    if [ -n ${lib.escapeShellArg cfg.providerService} ]; then
      for ready in /run/arbor-vaultd/ready/*; do
        if [ -f "$ready" ] && [ "$(stat -c '%a' "$ready" 2>/dev/null || printf 0)" = 644 ] \
          && ${pkgs.gnugrep}/bin/grep -Eq '^[0-9a-f]{64}$' "$ready"; then
          provider=1
          break
        fi
      done
      provider_state=$(${serviceState cfg.providerService})
      [ "$(printf '%s' "$provider_state" | ${pkgs.jq}/bin/jq -r .running)" = 1 ] || provider=0
    fi
    registry_installed=false
    transport_installed=false
    [ -x ${lib.escapeShellArg cfg.registryCommand} ] && registry_installed=true || true
    [ -x ${lib.escapeShellArg cfg.transportCommand} ] && transport_installed=true || true
    initialized=null
    sealed=null
    openbao_installed=false
    [ -x ${lib.escapeShellArg cfg.openbaoCommand} ] && openbao_installed=true || true
    if [ -x ${lib.escapeShellArg cfg.openbaoCommand} ]; then
      health=$(${pkgs.coreutils}/bin/timeout 2s ${lib.escapeShellArg cfg.openbaoCommand} status -format=json 2>/dev/null || true)
      if [ -n "$health" ]; then
        initialized=$(printf '%s' "$health" | ${pkgs.jq}/bin/jq -r 'if has("initialized") then .initialized else null end' 2>/dev/null || printf null)
        sealed=$(printf '%s' "$health" | ${pkgs.jq}/bin/jq -r 'if has("sealed") then .sealed else null end' 2>/dev/null || printf null)
      fi
    fi
    ${pkgs.jq}/bin/jq -n \
      --argjson registry "$registry" --argjson transport "$transport" --argjson vaultd "$vaultd" \
      --argjson initialized "$initialized" --argjson sealed "$sealed" --argjson provider "$provider" \
      --argjson registryInstalled "$registry_installed" --argjson transportInstalled "$transport_installed" \
      --argjson openbaoInstalled "$openbao_installed" --argjson registryReady "$registry_ready" --argjson providerState "$provider_state" \
      --argjson generatedAt "$generated_at" \
      '{version: 1, status: (if (($registryInstalled and ($registry.enabled == 1) and ($registry.running == 1)) and ($transportInstalled and ($transport.enabled == 1) and ($transport.running == 1)) and ($vaultd.enabled == 1 and $vaultd.running == 1) and ($registryReady == 1) and ($provider == 1) and ($initialized == true) and ($sealed == false)) then "healthy" else "degraded" end), healthy: (($registryInstalled and ($registry.enabled == 1) and ($registry.running == 1)) and ($transportInstalled and ($transport.enabled == 1) and ($transport.running == 1)) and ($vaultd.enabled == 1 and $vaultd.running == 1) and ($registryReady == 1) and ($provider == 1) and ($initialized == true) and ($sealed == false)), ready: (($registryInstalled and ($registry.enabled == 1) and ($registry.running == 1)) and ($transportInstalled and ($transport.enabled == 1) and ($transport.running == 1)) and ($vaultd.enabled == 1 and $vaultd.running == 1) and ($registryReady == 1) and ($provider == 1) and ($initialized == true) and ($sealed == false)), reason: (if (($registryInstalled == false) or ($registry.enabled != 1) or ($registry.running != 1)) then "registry unavailable" elif (($transportInstalled == false) or ($transport.enabled != 1) or ($transport.running != 1)) then "transport unavailable" elif (($vaultd.enabled != 1) or ($vaultd.running != 1)) then "vaultd unavailable" elif ($registryReady != 1) then "registry unavailable" elif ($initialized != true) then "OpenBao uninitialized" elif ($sealed != false) then "OpenBao sealed" elif ($provider != 1) then "provider unavailable" else null end), registry: ($registry + {installed: $registryInstalled, initialized: null, sealed: null, authenticated: null, ready: ($registryReady == 1)}), transport: ($transport + {installed: $transportInstalled, initialized: null, sealed: null, authenticated: null}), vaultd: ($vaultd + {installed: true, initialized: null, sealed: null, authenticated: null}), openbao: {installed: $openbaoInstalled, initialized: $initialized, sealed: $sealed, authenticated: null}, provider: ($providerState + {installed: true, initialized: null, sealed: null, authenticated: ($provider == 1)})}' >"$tmp"
    ${pkgs.jq}/bin/jq --argjson generatedAt "$generated_at" '. + {generatedAt: $generatedAt}' "$tmp" > "$tmp.generated"
    mv -f "$tmp.generated" "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$out"
  '';
in
{
  options.cluster.registry.runtime = {
    enable = mkEnableOption "the Arbor participant runtime service contract";
    registryService = mkOption {
      type = types.str;
      default = "arbor-registry.service";
      description = "Registry unit observed by the doctor contract.";
    };
    transportService = mkOption {
      type = types.str;
      default = "arbor-registry-transport.service";
      description = "Registry transport unit observed by the doctor contract.";
    };
    vaultdService = mkOption {
      type = types.str;
      default = "systemd-vaultd.service";
      description = "systemd-vaultd unit observed by the doctor contract.";
    };
    providerService = mkOption {
      type = types.str;
      default = "";
      description = "Optional provider unit whose active state is required for provider readiness.";
    };
    openbaoCommand = mkOption {
      type = types.str;
      default = "";
      description = "Optional runtime OpenBao CLI path; never initialized by this module.";
    };
    registryCommand = mkOption {
      type = types.str;
      default = "";
      description = "Optional runtime registry daemon path used only for installed-state reporting.";
    };
    transportCommand = mkOption {
      type = types.str;
      default = "";
      description = "Optional runtime transport daemon path used only for installed-state reporting.";
    };
    registryReadyCommand = mkOption {
      type = types.str;
      default = "";
      description = "Optional bounded, secret-free command that succeeds only when the Registry runtime is ready.";
    };
    statusPath = mkOption {
      type = types.str;
      default = "/run/arbor/doctor/status.json";
      description = "Secret-free runtime status document consumed by manager doctor.";
    };
    providerServices = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Provider units that must be wanted by the participant target.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.hasPrefix "/run/" cfg.statusPath;
        message = "cluster.registry.runtime.statusPath must be under /run";
      }
      {
        assertion = cfg.openbaoCommand == "" || lib.hasPrefix "/" cfg.openbaoCommand;
        message = "cluster.registry.runtime.openbaoCommand must be an absolute runtime path";
      }
      {
        assertion = cfg.registryReadyCommand == "" || lib.hasPrefix "/" cfg.registryReadyCommand;
        message = "cluster.registry.runtime.registryReadyCommand must be an absolute runtime path";
      }
      {
        assertion =
          lib.hasPrefix "/run/" cfg.statusPath
          && !lib.hasInfix "/../" cfg.statusPath
          && !lib.hasSuffix "/.." cfg.statusPath;
        message = "cluster.registry.runtime.statusPath must be a normalized path under /run";
      }
    ];
    systemd.targets.arbor-participant = {
      description = "Arbor participant runtime services";
      wantedBy = [ "multi-user.target" ];
      wants = [
        cfg.registryService
        cfg.transportService
        cfg.vaultdService
      ]
      ++ cfg.providerServices;
    };
    systemd.services.arbor-runtime-status = {
      description = "Arbor runtime doctor status contract";
      wantedBy = [ "arbor-participant.target" ];
      after = [ "arbor-participant.target" ];
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
