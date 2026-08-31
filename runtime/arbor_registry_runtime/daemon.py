"""Authenticated Unix-socket server for the durable Arbor Registry runtime."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import threading
from pathlib import Path
from typing import Any

from .runtime import OrbitDBProvider, Runtime


def _config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("registry config must be an object")
    return value


def _token(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise ValueError("registry socket token is too short")
    return value


class RegistryServer:
    def __init__(self, config: dict[str, Any]):
        self.socket_path = Path(config.get("socket", "/run/arbor-registry/registry.sock"))
        transport_socket = Path(config.get("transportSocket", "/run/arbor-registry-transport/transport.sock"))
        self.token = _token(Path(config["tokenFile"]))
        authorities_path = Path(config.get("bootstrapAuthoritiesFile", "/var/lib/arbor-registry/bootstrap-authorities.json"))
        authorities: dict[str, str] = {}
        if authorities_path.exists():
            value = json.loads(authorities_path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                authorities = value.get("keys", value)
        self.runtime = Runtime(
            config.get("stateDir", "/var/lib/arbor-registry"),
            OrbitDBProvider(transport_socket, config.get("stream", "registry"), token=self.token),
            authorities,
            authority_issuers=set(config.get("authorityIssuers", authorities)),
        )
        self.listener: socket.socket | None = None
        self.stop_event = threading.Event()

    def handle(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict) or request.get("token") != self.token:
            return {"ok": False, "code": "authentication_failed"}
        operation = request.get("operation")
        if operation == "health":
            return {"ok": True, "status": "ok"}
        if operation == "status":
            return {"ok": True, "status": "ok", "runtime": self.runtime.status()}
        if operation in {"sync", "transport-update"}:
            try:
                result = self.runtime.sync(
                    max_pages=request.get("maxPages", 8),
                    page_size=request.get("pageSize", 100),
                )
            except (TypeError, ValueError):
                return {"ok": False, "code": "invalid_sync_bounds"}
            return {"ok": True, "sync": result, "runtime": self.runtime.status()}
        if operation == "accepted":
            return {"ok": True, "records": self.runtime.accepted()}
        if operation == "projection":
            return {"ok": True, "records": self.runtime.projection()}
        if operation == "quarantine":
            return {"ok": True, "records": self.runtime.quarantine()}
        if operation == "ingest":
            records = request.get("records")
            if not isinstance(records, list):
                return {"ok": False, "code": "invalid_records"}
            return {"ok": True, "outcomes": self.runtime.ingest(records)}
        return {"ok": False, "code": "unsupported_operation"}

    def serve(self) -> None:
        self.socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        self.listener.listen(32)
        self.listener.settimeout(1.0)
        while not self.stop_event.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            with connection:
                raw = connection.recv(1024 * 1024)
                try:
                    request = json.loads(raw.split(b"\n", 1)[0])
                    reply = self.handle(request)
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    reply = {"ok": False, "code": "invalid_request"}
                connection.sendall(json.dumps(reply, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def close(self) -> None:
        self.stop_event.set()
        if self.listener is not None:
            self.listener.close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self.runtime.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arbor-registryd")
    parser.add_argument("--config", default=os.environ.get("ARBOR_REGISTRY_CONFIG", "/etc/arbor-registry/config.json"))
    args = parser.parse_args(argv)
    server = RegistryServer(_config(Path(args.config)))
    signal.signal(signal.SIGTERM, lambda *_: server.stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: server.stop_event.set())
    try:
        server.serve()
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
