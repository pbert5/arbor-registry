{ buildNpmPackage, nodejs_22 }:
buildNpmPackage {
  pname = "arbor-registryd";
  version = "0.1.0";
  src = ./.;
  npmDepsHash = "sha256-qFD1rr+NDdHvkcOs4yOti8WrGeP8piKVi1UwDUR/qJs=";
  inherit nodejs_22;
  dontNpmBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/lib/arbor-registryd" "$out/bin"
    cp -R . "$out/lib/arbor-registryd/source"
    makeWrapper ${nodejs_22}/bin/node "$out/bin/arbor-registryd" \
      --add-flags "$out/lib/arbor-registryd/source/registryd.mjs"
    runHook postInstall
  '';
  meta.mainProgram = "arbor-registryd";
}
