"""Runtime-only adapter for the pinned systemd-vaultd JSON contract."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _parse_credential(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition(":")
    if not separator or not name or not path.startswith("/") or "/nix/store/" in path:
        raise ValueError("credentials must be NAME:/runtime/path")
    if not name.replace("_", "").replace("-", "").isalnum():
        raise ValueError(f"invalid credential name: {name}")
    return name, Path(path)


def write_service(args: argparse.Namespace) -> bool:
    output_dir = args.output_dir
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = output_dir / f"{args.service}.service.json"
    lock_path = output_dir / f".{args.service}.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        values = {}
        for item in args.credential:
            name, path = _parse_credential(item)
            try:
                values[name] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise RuntimeError(f"credential {name} is not ready") from error
        content = (json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            if output.read_bytes() == content:
                return False
        except FileNotFoundError:
            pass
        fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output_dir)
        try:
            os.fchmod(fd, 0o400)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, output)
            os.chmod(output, 0o400)
            directory_fd = os.open(output_dir, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize provider files for systemd-vaultd")
    parser.add_argument("--service", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("/run/systemd-vaultd/secrets"))
    parser.add_argument("--credential", action="append", required=True)
    parser.add_argument("--restart")
    args = parser.parse_args()
    try:
        changed = write_service(args)
        if changed and args.restart:
            result = subprocess.run(
                ["/run/current-system/sw/bin/systemctl", "try-restart", args.restart],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
            if result.returncode:
                raise RuntimeError(f"restart command failed with exit status {result.returncode}")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"arbor-systemd-vaultd-bridge: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
