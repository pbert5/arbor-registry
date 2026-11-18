{
  pkgs,
  runtime,
  transport,
}:
let
  python = pkgs.python3.withPackages (ps: [
    ps.pexpect
    ps.magic-wormhole-mailbox-server
  ]);
in
pkgs.runCommand "arbor-registry-existing-root-pair"
  {
    nativeBuildInputs = [
      python
      runtime
      transport
    ];
  }
  ''
    python ${./existing-root-pair.py}
    touch "$out"
  ''
