"""Bounded Manager protocol client for the running Registry's authenticated socket."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, TextIO

from .daemon import _config, _token

MAX_BYTES = 65536
OPERATIONS = {"identity/inspect", "identity/init-self", "registry/summary"}


def validate_request(request: Any) -> None:
    if (not isinstance(request, dict)
            or request.get("protocol") != "arbor-manager/runtime-adapter"
            or type(request.get("version")) is not int or request["version"] != 1
            or request.get("operation") not in OPERATIONS
            or not isinstance(request.get("data"), dict)
            or set(request) != {"protocol", "version", "operation", "data"}
            or set(request["data"]) - {"nodeId", "domain"}):
        raise ValueError("invalid runtime adapter request")


def run(source: TextIO, output: TextIO, config_path: Path) -> int:
    try:
        raw = source.read(MAX_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_BYTES:
            raise ValueError("request too large")
        request = json.loads(raw)
        validate_request(request)
        config = _config(config_path)
        request["token"] = _token(Path(config["tokenFile"]))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(30)
            client.connect(config.get("socket", "/run/arbor-registry/registry.sock"))
            client.sendall(json.dumps(request).encode() + b"\n")
            with client.makefile("rb") as stream:
                response = stream.readline(MAX_BYTES + 1)
        if len(response) > MAX_BYTES or not response.endswith(b"\n"):
            raise ValueError("invalid response size")
        result = json.loads(response)
        if (not isinstance(result, dict)
                or result.get("format") != "arbor-manager/runtime-response"
                or type(result.get("version")) is not int or result["version"] != 1
                or result.get("status") != "accepted"):
            raise ValueError("runtime operation failed")
        # Fixed public projection, even if a misconfigured server returns extras.
        fields = {"format", "version", "status", "operation", "nodeId", "initialized",
                  "generation", "publicFingerprint", "localGenesis", "selfRooted", "parents", "peers"}
        safe = {key: value for key, value in result.items()
                if key in fields and (value is None or type(value) in (str, int, bool))}
        for field, names in (("records", ("total", "accepted", "quarantined")),
                             ("projection", ("total",))):
            if isinstance(result.get(field), dict):
                safe[field] = {name: result[field][name] for name in names
                               if type(result[field].get(name)) is int and result[field][name] >= 0}
        output.write(json.dumps(safe, sort_keys=True) + "\n")
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        # Neither server errors nor config/token contents reach stdout/stderr.
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arbor-registry-manager-adapter")
    parser.add_argument("--config", default=os.environ.get("ARBOR_REGISTRY_CONFIG", "/etc/arbor-registry/config.json"))
    args = parser.parse_args(argv)
    return run(sys.stdin, sys.stdout, Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
