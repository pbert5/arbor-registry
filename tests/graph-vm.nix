{ module, pkgs }:
let
  runtime = pkgs.callPackage ../runtime/package.nix { };
  transport = pkgs.callPackage ../transport/package.nix { };
  python = pkgs.python3.withPackages (ps: [
    ps.pynacl
    runtime
  ]);
  realm = "arbor-graph-acceptance-v1";
  node =
    { hostname, address }:
    {
      imports = [ module ];
      system.stateVersion = "25.05";
      networking.hostName = hostname;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [
        {
          inherit address;
          prefixLength = 24;
        }
      ];
      virtualisation.memorySize = 1536;
      environment.systemPackages = [
        pkgs.jq
        python
        runtime
        transport
      ];
      environment.etc."arbor-test/graph.py".source = ./graph-vm.py;
      cluster.registry.runtime = {
        enable = true;
        runtimePackage = runtime;
        transportPackage = transport;
        transportRealmId = realm;
        transportProtocolEpoch = 1;
        transportListen = [ "/ip4/0.0.0.0/tcp/4001" ];
        socket = "/run/arbor-registry/registry.sock";
        transportSocket = "/run/arbor-registry-transport/transport.sock";
        tokenFile = "/run/arbor-registry/socket-token";
        bootstrapAuthoritiesFile = "/run/arbor-test/bootstrap-authorities.json";
        authorityIssuers = [ "root-a" ];
      };
      # The graph test creates the authority key at runtime. Keep the
      # production target from starting Registry until that public key map
      # has been installed by the test harness.
      systemd.targets.arbor-participant.wants = pkgs.lib.mkForce [
        "arbor-registry-transport.service"
      ];
      systemd.services.arbor-registry.wantedBy = pkgs.lib.mkForce [ ];
    };
in
pkgs.testers.nixosTest {
  name = "arbor-self-root-graph-vm";
  nodes = {
    root-a = node {
      hostname = "root-a";
      address = "10.42.0.10";
    };
    root-b = node {
      hostname = "root-b";
      address = "10.42.0.11";
    };
    child = node {
      hostname = "child";
      address = "10.42.0.12";
    };
    grandchild = node {
      hostname = "grandchild";
      address = "10.42.0.13";
    };
  };
  testScript = builtins.readFile ./graph-vm-test.py;
}
