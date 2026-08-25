{
  description = "Arbor Registry: pure signed-record reconciliation and graph library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systemd-vaultd.url = "github:numtide/systemd-vaultd";
    systemd-vaultd.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { nixpkgs, systemd-vaultd, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      registry = import ./lib { lib = nixpkgs.lib; };
      nixosModule = import ./modules/nixos.nix;
      vaultRuntimeModule = import ./modules/vault-runtime.nix;
    in
    {
      lib = registry;
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          runtime = import ./runtime/package.nix { inherit (pkgs) lib python3Packages; };
          transport = import ./transport/package.nix { inherit (pkgs) buildNpmPackage nodejs_22; };
        in
        {
          arbor-registry-runtime = runtime;
          arbor-registry-transport = transport;
          default = runtime;
        }
      );
      nixosModules = {
        default = nixosModule;
        vault-runtime = vaultRuntimeModule;
        vault-runtime-upstream = {
          imports = [
            systemd-vaultd.nixosModules.systemdVaultd
            systemd-vaultd.nixosModules.vaultAgent
            vaultRuntimeModule
          ];
          cluster.vault.runtime.useUpstreamVaultd = true;
        };
      };
      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixfmt-tree);
      checks = forAllSystems (system: {
        invariants = import ./tests/invariants.nix {
          inherit registry;
          pkgs = import nixpkgs { inherit system; };
        };
        modules = import ./tests/modules.nix {
          module = nixosModule;
          pkgs = import nixpkgs { inherit system; };
        };
        peers = import ./tests/peers.nix {
          inherit registry;
          pkgs = import nixpkgs { inherit system; };
        };
        recovery = import ./tests/recovery.nix {
          inherit registry;
          pkgs = import nixpkgs { inherit system; };
        };
        runtime =
          (import nixpkgs { inherit system; }).runCommand "arbor-registry-runtime-tests"
            {
              nativeBuildInputs = [
                ((import nixpkgs { inherit system; }).python3.withPackages (ps: [ ps.pynacl ]))
              ];
            }
            ''
              export PYTHONPATH=${./runtime}
              python -m unittest discover -s ${./runtime/tests} -v
              touch $out
            '';
        transport =
          let
            pkgs = import nixpkgs { inherit system; };
            package = import ./transport/package.nix { inherit (pkgs) buildNpmPackage nodejs_22; };
          in
          pkgs.runCommand "arbor-registry-transport-tests" { nativeBuildInputs = [ pkgs.nodejs_22 ]; } ''
            node --check ${./transport}/registryd.mjs
            node --check ${./transport}/test/registryd.test.mjs
            node --test ${package}/lib/arbor-registryd/source/test/*.test.mjs
            touch $out
          '';
        vault-runtime = import ./tests/vault-runtime.nix {
          module = vaultRuntimeModule;
          pkgs = import nixpkgs { inherit system; };
        };
        vault-runtime-contract = import ./tests/vault-runtime-contract.nix {
          module = vaultRuntimeModule;
          pkgs = import nixpkgs { inherit system; };
        };
        vault-upstream = import ./tests/vault-upstream.nix {
          inherit nixpkgs system;
          pkgs = import nixpkgs { inherit system; };
          module = vaultRuntimeModule;
          upstreamModules = [
            systemd-vaultd.nixosModules.systemdVaultd
            systemd-vaultd.nixosModules.vaultAgent
          ];
        };
        vault-upstream-vm = import ./tests/vault-upstream-vm.nix {
          module = vaultRuntimeModule;
          pkgs = import nixpkgs { inherit system; };
          upstreamModules = [
            systemd-vaultd.nixosModules.systemdVaultd
            systemd-vaultd.nixosModules.vaultAgent
          ];
        };
        openbao-runtime =
          let
            pkgs = import nixpkgs { inherit system; };
            runtime = import ./runtime/package.nix {
              inherit (pkgs) lib python3Packages;
            };
          in
          pkgs.runCommand "arbor-registry-openbao-runtime"
            {
              nativeBuildInputs = [
                pkgs.bash
                pkgs.coreutils
                pkgs.curl
                pkgs.openbao
              ];
            }
            ''
              set -euo pipefail
              work=$(mktemp -d)
              mkdir -p "$work/home"
              export HOME="$work/home"
              port=18273
              ${pkgs.openbao}/bin/bao server -dev \
                -dev-root-token-id=arbor-test-root \
                -dev-listen-address="127.0.0.1:$port" \
                >"$work/openbao.log" 2>&1 &
              server_pid=$!
              cleanup() {
                kill "$server_pid" 2>/dev/null || true
                wait "$server_pid" 2>/dev/null || true
              }
              trap cleanup EXIT
              export BAO_ADDR="http://127.0.0.1:$port"
              ready=false
              for attempt in $(seq 1 100); do
                if ${pkgs.curl}/bin/curl --fail --silent "$BAO_ADDR/v1/sys/health" >/dev/null; then ready=true; break; fi
                sleep 0.1
              done
              if [ "$ready" != true ]; then cat "$work/openbao.log"; exit 1; fi
              token_file="$work/token"
              printf '%s\n' arbor-test-root >"$token_file"
              chmod 600 "$token_file"
              secret_v1="runtime-$(date +%s%N)"
              BAO_TOKEN=arbor-test-root ${pkgs.openbao}/bin/bao kv put secret/arbor/db url="$secret_v1" >/dev/null
              ${runtime}/bin/arbor-openbao-provider \
                --address "$BAO_ADDR" \
                --token-file "$token_file" \
                --path secret/data/arbor/db \
                --field url \
                --output "$work/credential" \
                --ready "$work/ready"
              test "$(<"$work/credential")" = "$secret_v1"
              test "$(stat -c '%a' "$work/credential")" = 600
              test "$(stat -c '%a' "$work/ready")" = 644
              test "$(wc -c <"$work/ready")" = 65
              secret_v2="runtime-$(date +%s%N)"
              BAO_TOKEN=arbor-test-root ${pkgs.openbao}/bin/bao kv put secret/arbor/db url="$secret_v2" >/dev/null
              ${runtime}/bin/arbor-openbao-provider \
                --address "$BAO_ADDR" \
                --token-file "$token_file" \
                --path secret/data/arbor/db \
                --field url \
                --output "$work/credential" \
                --ready "$work/ready"
              test "$(<"$work/credential")" = "$secret_v2"
              if grep -F "$secret_v2" "$token_file" "$work/ready"; then exit 1; fi
              touch "$out"
            '';
      });
    };
}
