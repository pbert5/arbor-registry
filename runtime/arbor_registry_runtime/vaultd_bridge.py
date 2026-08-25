"""Runtime-only adapter for the pinned systemd-vaultd JSON contract."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


_SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:%-]{0,127}$")


def _validate_service(value: str) -> str:
    if not _SERVICE.fullmatch(value) or value in {".", ".."} or ".." in value:
        raise ValueError("invalid systemd service name")
    return value


def _parse_credential(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition(":")
    if (
        not separator
        or not name
        or not path.startswith(("/run/", "/var/lib/arbor/"))
        or "/nix/store/" in path
    ):
        raise ValueError("credentials must be NAME:/runtime/path")
    if not name.replace("_", "").replace("-", "").isalnum():
        raise ValueError(f"invalid credential name: {name}")
    return name, Path(path)


def _read_credential(path: Path, name: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"credential {name} is not ready") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError(f"credential {name} is not a private regular file")
        raw = os.read(fd, 1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError(f"credential {name} is too large")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError(f"credential {name} is not UTF-8") from error
    finally:
        os.close(fd)


def write_service(args: argparse.Namespace) -> bool:
    _validate_service(args.service)
    if args.output_dir != Path("/run/systemd-vaultd/secrets"):
        raise ValueError("output directory must be /run/systemd-vaultd/secrets")
    output_dir = args.output_dir
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_info = os.lstat(output_dir)
    if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
        raise ValueError("output directory must be a real directory")
    os.chmod(output_dir, 0o700)
    output = output_dir / f"{args.service}.service.json"
    lock_path = output_dir / f".{args.service}.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        with os.fdopen(lock_fd, "a+") as lock:
            lock_fd = -1
            return _write_locked(args, output_dir, output, lock)
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)


def _write_locked(args: argparse.Namespace, output_dir: Path, output: Path, lock) -> bool:
        fcntl.flock(lock, fcntl.LOCK_EX)
        values = {}
        for item in args.credential:
            name, path = _parse_credential(item)
            values[name] = _read_credential(path, name)
        content = (json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            output_info = os.lstat(output)
            if stat.S_ISLNK(output_info.st_mode) or not stat.S_ISREG(output_info.st_mode):
                raise ValueError("output file must be a real regular file")
            if stat.S_IMODE(output_info.st_mode) & 0o077:
                raise ValueError("output file must not be group/world accessible")
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
        if args.restart:
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
