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
      vaultRuntimeSystemdVaultdModule = import ./modules/vault-runtime-systemd-vaultd.nix;
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
        vault-runtime-systemd-vaultd = vaultRuntimeSystemdVaultdModule;
      };
      nixosTests = forAllSystems (system: {
        vault-runtime-openbao = import ./tests/vault-runtime-openbao.nix {
          pkgs = import nixpkgs { inherit system; };
          inherit systemd-vaultd;
          arborVaultRuntimeModule = vaultRuntimeModule;
          arborVaultRuntimeSystemdVaultdModule = vaultRuntimeSystemdVaultdModule;
        };
      });
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
          (import nixpkgs { inherit system; }).runCommand "arbor-registry-transport-tests"
            { nativeBuildInputs = [ (import nixpkgs { inherit system; }).nodejs_22 ]; }
            ''
              node --check ${./transport}/registryd.mjs
              node --check ${./transport}/test/registryd.test.mjs
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
      });
    };
}
