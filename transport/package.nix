{ buildNpmPackage, nodejs_22 }:
buildNpmPackage {
  pname = "arbor-registry-transport";
  version = "0.1.0";
  src = ./.;
  npmDepsHash = "sha256-qFD1rr+NDdHvkcOs4yOti8WrGeP8piKVi1UwDUR/qJs=";
  inherit nodejs_22;
  dontNpmBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/lib/arbor-registry-transport" "$out/bin"
    cp -R . "$out/lib/arbor-registry-transport/source"
    makeWrapper ${nodejs_22}/bin/node "$out/bin/arbor-registry-transport" \
      --add-flags "$out/lib/arbor-registry-transport/source/registryd.mjs"
    runHook postInstall
  '';
  meta.mainProgram = "arbor-registry-transport";
}
