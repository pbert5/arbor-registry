{ module, pkgs }:
let
  runtime = pkgs.callPackage ../runtime/package.nix { };
  transport = pkgs.callPackage ../transport/package.nix { };
  python = pkgs.python3.withPackages (ps: [
    ps.pynacl
    runtime
  ]);
  node =
    {
      hostname,
      address,
      bootstrap,
    }:
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
      environment.variables.PYTHONPATH = "${runtime}/lib/${pkgs.python3.sitePackages}";
      environment.etc."arbor-test/fixture.py".source = ./two-node-convergence-fixture.py;
      cluster.registry.runtime = {
        enable = true;
        runtimePackage = runtime;
        transportPackage = transport;
        transportRealmId = "arbor-two-node-live-v1";
        transportProtocolEpoch = 1;
        transportListen = [ "/ip4/0.0.0.0/tcp/4001" ];
        socket = "/run/arbor-registry/registry.sock";
        transportSocket = "/run/arbor-registry-transport/transport.sock";
        tokenFile = "/run/arbor-test/socket-token";
        bootstrapAuthoritiesFile = "/run/arbor-test/bootstrap-authorities.json";
        authorityIssuers = [ "root-a" ];
        syncInterval = 1;
        syncMaxBackoff = 2;
      };
      # Only A may be brought up by the participant target.  B must remain
      # stopped until the test has read A's semantic transport status and
      # installed its address/peer bootstrap configuration.
      systemd.targets.arbor-participant.wants = pkgs.lib.mkForce (
        if bootstrap then [ "arbor-registry-transport.service" ] else [ ]
      );
      systemd.services.arbor-registry-transport.wantedBy = pkgs.lib.mkForce (
        if bootstrap then [ "arbor-participant.target" ] else [ ]
      );
      systemd.services.arbor-registry.wantedBy = pkgs.lib.mkForce [ ];
      systemd.tmpfiles.rules = [ "d /run/arbor-test 0750 arbor-registry arbor-registry -" ];
    };
in
pkgs.testers.nixosTest {
  name = "arbor-registry-two-node-live-convergence";
  nodes = {
    node-a = node {
      hostname = "node-a";
      address = "10.42.0.10";
      bootstrap = true;
    };
    node-b = node {
      hostname = "node-b";
      address = "10.42.0.11";
      bootstrap = false;
    };
  };
  testScript = builtins.readFile ./two-node-convergence-vm.py;
}
