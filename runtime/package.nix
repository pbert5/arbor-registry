{ lib, python3Packages }:
python3Packages.buildPythonApplication {
  pname = "arbor-registry-runtime";
  version = "0.1.0";
  pyproject = true;
  build-system = [ python3Packages.setuptools ];
  src = ./.;
  propagatedBuildInputs = [ python3Packages.pynacl ];
  dontUsePytest = true;
  installCheckPhase = "true";
  meta = {
    description = "Local durable runtime for signed Arbor Registry records";
    license = lib.licenses.mit;
  };
}
