"""Authenticated Unix-socket server for the durable Arbor Registry runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Any

from .runtime import OrbitDBProvider, Runtime, generate_keypair, load_keypair


class SyncWorker:
    """One bounded, stoppable consumer loop owned by the registry daemon."""

    def __init__(self, sync: Any, *, interval: float, max_backoff: float,
                 max_pages: int, page_size: int):
        if interval <= 0 or max_backoff < interval:
            raise ValueError("sync interval and backoff are invalid")
        self.sync = sync
        self.interval, self.max_backoff = interval, max_backoff
        self.max_pages, self.page_size = max_pages, page_size
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._backoff = interval
        self._status: dict[str, Any] = {"state": "idle", "lastError": None}

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self.stop_event.clear()
            self._backoff = self.interval
            self._thread = threading.Thread(target=self._run, name="arbor-registry-sync", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        delay = 0.0
        while not self.stop_event.wait(delay):
            try:
                result = self.sync(max_pages=self.max_pages, page_size=self.page_size)
                state = result.get("state") if isinstance(result, dict) else "idle"
                with self._lock:
                    self._status = {"state": "error" if state == "degraded" else "ok",
                                    "lastError": result.get("lastError") if isinstance(result, dict) else None,
                                    "lastResult": result, "lastSyncAt": time.time()}
                if state == "degraded":
                    delay = self._backoff
                    self._backoff = min(self.max_backoff, self._backoff * 2)
                elif isinstance(result, dict) and result.get("backlog"):
                    self._backoff = self.interval
                    delay = 0.0
                else:
                    self._backoff = self.interval
                    delay = self.interval
            except Exception as error:  # provider outages are expected and retried
                with self._lock:
                    self._status = {"state": "error", "lastError": f"{type(error).__name__}: {error}",
                                    "lastSyncAt": time.time()}
                delay = self._backoff
                self._backoff = min(self.max_backoff, self._backoff * 2)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def stop(self) -> bool:
        self.stop_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self.max_backoff + 1.0))
        return thread is None or not thread.is_alive()


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
        self.key_dir = Path(config.get("keyDir", self.runtime.state_dir / "keys"))
        self._runtime_lock = threading.RLock()
        self.sync_worker = SyncWorker(
            lambda **kwargs: self._runtime_call(self.runtime.sync, **kwargs),
            interval=float(config.get("syncInterval", 5.0)),
            max_backoff=float(config.get("syncMaxBackoff", 60.0)),
            max_pages=int(config.get("syncMaxPages", 4)),
            page_size=int(config.get("syncPageSize", 100)),
        )
        self.listener: socket.socket | None = None
        self.stop_event = threading.Event()

    def _runtime_call(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        lock = getattr(self, "_runtime_lock", None)
        if lock is None:
            return operation(*args, **kwargs)
        with lock:
            return operation(*args, **kwargs)

    def handle(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict) or request.get("token") != self.token:
            return {"ok": False, "code": "authentication_failed"}
        operation = request.get("operation")
        if operation in {"identity/inspect", "identity/init-self", "registry/summary"}:
            try:
                return self._runtime_call(self._manager_request, request)
            except (OSError, RuntimeError):
                return {"format": "arbor-manager/runtime-response", "version": 1, "status": "unavailable"}
            except (ValueError, TypeError):
                return {"format": "arbor-manager/runtime-response", "version": 1, "status": "conflict"}
        if operation == "health":
            return {"ok": True, "status": "ok"}
        if operation == "status":
            return {"ok": True, "status": "ok", "runtime": self._runtime_call(self.runtime.status),
                    "syncWorker": self.sync_worker.status()}
        if operation in {"sync", "transport-update"}:
            try:
                result = self._runtime_call(self.runtime.sync,
                    max_pages=request.get("maxPages", 8),
                    page_size=request.get("pageSize", 100),
                )
            except (TypeError, ValueError):
                return {"ok": False, "code": "invalid_sync_bounds"}
            return {"ok": True, "sync": result, "runtime": self._runtime_call(self.runtime.status)}
        if operation == "accepted":
            return {"ok": True, "records": self._runtime_call(self.runtime.accepted)}
        if operation == "projection":
            return {"ok": True, "records": self._runtime_call(self.runtime.projection)}
        if operation == "quarantine":
            return {"ok": True, "records": self._runtime_call(self.runtime.quarantine)}
        if operation == "ingest":
            records = request.get("records")
            if not isinstance(records, list):
                return {"ok": False, "code": "invalid_records"}
            return {"ok": True, "outcomes": self._runtime_call(self.runtime.ingest, records)}
        return {"ok": False, "code": "unsupported_operation"}

    def _manager_request(self, request: dict[str, Any]) -> dict[str, Any]:
        from .manager_adapter import validate_request

        validate_request({key: value for key, value in request.items() if key != "token"})
        operation, data = request["operation"], request["data"]
        local = self.runtime.local_authorities
        node_id = data.get("nodeId")
        if node_id is None and len(local) > 1:
            raise ValueError("local identity is ambiguous")
        if node_id is None and operation == "identity/inspect" and len(local) <= 1:
            node_id = next(iter(local), None)
        if node_id is None and operation == "identity/inspect":
            return {"format": "arbor-manager/runtime-response", "version": 1,
                    "status": "accepted", "operation": operation, "nodeId": None,
                    "initialized": False, "localGenesis": False}
        if not isinstance(node_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
            raise ValueError("invalid node identifier")
        if operation == "identity/init-self":
            domain = data.get("domain")
            if not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", domain):
                raise ValueError("invalid authority domain")
            if local and (set(local) != {node_id} or local[node_id][0] != domain):
                raise ValueError("conflicting local genesis")
            key = load_keypair(self.key_dir, node_id)
            if node_id in local:
                if key is None or key.public_key != local[node_id][1]:
                    raise ValueError("key conflicts with local genesis")
            else:
                # Existing unclaimed identity material is an operator boundary.
                if key is not None or any(self.key_dir.glob("*.private")) or any(self.key_dir.glob("*.public")):
                    raise ValueError("unclaimed key material")
                if self.runtime.public_keys.get(node_id) is not None:
                    raise ValueError("identity is already known")
                key = generate_keypair(self.key_dir, node_id)
            self.runtime.node_key = key
            result = self.runtime.local_genesis(node_id, domain)
            if result["status"] != "accepted":
                raise ValueError("local genesis was not accepted")
        elif node_id in local:
            key = load_keypair(self.key_dir, node_id)
            if key is None or key.public_key != local[node_id][1]:
                raise ValueError("key conflicts with local genesis")
        summary = self.runtime.state_summary(node_id)
        identity = summary["localIdentity"]
        public = local.get(node_id, (None, None))[1]
        return {"format": "arbor-manager/runtime-response", "version": 1,
                "status": "accepted", "operation": operation, "nodeId": node_id,
                "initialized": identity["initialized"], "generation": identity["generation"],
                "localGenesis": identity["localGenesis"], "selfRooted": identity["selfRooted"],
                "publicFingerprint": hashlib.sha256(public.encode()).hexdigest() if public else None,
                "parents": identity["parentCount"], "peers": identity["peerCount"],
                "records": {"total": summary["records"]["records"],
                            "accepted": summary["records"]["accepted"],
                            "quarantined": summary["records"]["quarantined"]},
                "projection": summary["projection"]}

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
        self.sync_worker.start()
        try:
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
        finally:
            self.sync_worker.stop()

    def close(self) -> None:
        self.stop_event.set()
        self.sync_worker.stop()
        if self.listener is not None:
            self.listener.close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        # Do not close SQLite while a worker still owns a runtime operation.
        with self._runtime_lock:
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
