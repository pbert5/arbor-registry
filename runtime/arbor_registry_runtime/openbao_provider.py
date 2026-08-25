"""Runtime-only OpenBao credential fetch and materialization boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _json_value(response: Any, field: str) -> str:
    """Accept command output and both KV-v1/KV-v2 OpenBao response shapes."""
    candidates = [response]
    if isinstance(response, dict):
        data = response.get("data")
        candidates.append(data)
        if isinstance(data, dict):
            candidates.append(data.get("data"))
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get(field), str):
            return candidate[field]
    raise ValueError(f"provider response does not contain string field {field!r}")


def _command_fetch(command: Sequence[str], request: dict[str, str]) -> str:
    result = subprocess.run(
        list(command), input=(json.dumps(request, sort_keys=True) + "\n").encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env={**os.environ, "ARBO_RUNTIME_PROVIDER": "openbao-command"},
    )
    if result.returncode:
        raise RuntimeError(f"provider command failed with exit status {result.returncode}")
    try:
        response = json.loads(result.stdout.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("provider command returned malformed JSON") from error
    return _json_value(response, request["field"])


def _http_fetch(address: str, token_file: Path | None, namespace: str | None,
                path: str, field: str, timeout: float) -> str:
    url = address.rstrip("/") + "/v1/" + path.lstrip("/")
    headers = {"Accept": "application/json"}
    if token_file is not None:
        headers["X-Vault-Token"] = token_file.read_text(encoding="utf-8").strip()
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as response:  # noqa: S310
            payload = json.loads(response.read(1024 * 1024).decode())
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"OpenBao request failed: {type(error).__name__}") from error
    return _json_value(payload, field)


def _atomic_write(path: Path, value: str) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256(value.encode()).hexdigest()
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return digest


def _mark_ready(path: Path, digest: str) -> None:
    _atomic_write(path, digest + "\n")
    os.chmod(path, 0o644)


def run(args: argparse.Namespace) -> int:
    command = args.provider_command
    if command is None and not args.address:
        raise ValueError("one of --provider-command or --address is required")
    token_file = Path(args.token_file) if args.token_file else None
    previous: str | None = None
    while True:
        request = {"path": args.path, "field": args.field}
        if command:
            value = _command_fetch(command, request)
        else:
            value = _http_fetch(args.address, token_file, args.namespace, args.path, args.field, args.timeout)
        digest = hashlib.sha256(value.encode()).hexdigest()
        changed = previous is not None and digest != previous
        if previous != digest or not args.output.exists():
            _atomic_write(args.output, value)
            _mark_ready(args.ready, digest)
        if changed and args.restart_command:
            result = subprocess.run(args.restart_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False)
            if result.returncode:
                raise RuntimeError(f"restart command failed with exit status {result.returncode}")
        previous = digest
        if not args.watch:
            return 0
        time.sleep(args.interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch one OpenBao credential at runtime")
    parser.add_argument("--path", required=True)
    parser.add_argument("--field", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--address")
    parser.add_argument("--namespace")
    parser.add_argument("--token-file")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--provider-command", nargs="+")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--restart-command", nargs="+")
    args = parser.parse_args()
    if args.timeout <= 0 or args.interval <= 0:
        parser.error("--timeout and --interval must be positive")
    try:
        return run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"arbor-openbao-provider: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
