"""Durable record ingestion; private keys and public state have separate roots."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import fcntl
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, TypeAlias

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


SCHEMAS = frozenset({"node-identity", "relationship", "capability", "service", "endpoint"})
ProviderCursor: TypeAlias = int | str


def canonical_json(value: Any) -> bytes:
    """The wire canonical form: UTF-8, sorted keys, no insignificant whitespace."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _without_signature(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "signature"}


def _key(record: dict[str, Any]) -> str:
    return f"{record.get('recordId')}:{record.get('recordVersion')}"


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class RuntimeKey:
    issuer: str
    signing_key: SigningKey

    @property
    def public_key(self) -> str:
        return _b64(bytes(self.signing_key.verify_key))

    def sign(self, unsigned: dict[str, Any]) -> str:
        return _b64(self.signing_key.sign(canonical_json(unsigned)).signature)


def generate_keypair(
    key_dir: Path,
    issuer: str,
    *,
    rotation: bool = False,
    generation: int | None = None,
) -> RuntimeKey:
    """Create runtime key material without silently replacing an identity.

    A generation writes ``<issuer>.g<generation>`` files, preserving older
    generations. Replacing the active ``<issuer>`` files requires the explicit
    ``rotation=True`` operation.
    """
    if (not isinstance(issuer, str) or not issuer or issuer in {".", ".."}
            or issuer != Path(issuer).name or "/" in issuer or "\\" in issuer or "\x00" in issuer):
        raise ValueError("issuer must be a single safe path component")
    if generation is not None and (isinstance(generation, bool) or not isinstance(generation, int) or generation < 1):
        raise ValueError("generation must be a positive integer")
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = RuntimeKey(issuer, SigningKey.generate())
    suffix = f".g{generation}" if generation is not None else ""
    private_path = key_dir / f"{issuer}{suffix}.private"
    public_path = key_dir / f"{issuer}{suffix}.public"
    if not rotation and (private_path.exists() or public_path.exists()):
        raise FileExistsError(f"key material already exists for {issuer}{suffix}; use rotation=True or a new generation")
    private_path.write_text(_b64(bytes(key.signing_key)), encoding="ascii")
    os.chmod(private_path, 0o600)
    public_path.write_text(key.public_key + "\n", encoding="ascii")
    return key


class Provider(ABC):
    """Append-only raw transport contract used by :class:`Runtime`.

    Providers are deliberately transport-only.  ``append`` must durably
    retain the exact record and may return its zero-based cursor.  Repeating
    the same record must return the original cursor; a different record with
    the same logical key remains a transport entry for the runtime to
    quarantine.  ``fetch`` returns ``(cursor, record)`` pairs in strictly
    increasing cursor order and must enforce its own bounded page size.

    Validation, authority, reconciliation, and materialization stay in
    ``Runtime`` so an external provider cannot grant trust by accepting a
    record.  A network adapter can implement this contract later without
    becoming part of Nix evaluation.
    """

    @abstractmethod
    def append(self, record: dict[str, Any]) -> ProviderCursor: ...

    @abstractmethod
    def fetch(self, cursor: ProviderCursor = 0, limit: int = 100) -> list[tuple[ProviderCursor, dict[str, Any]]]: ...


class FileProvider(Provider):
    """Append-only JSONL transport. Cursors are line offsets, never timestamps."""

    def __init__(self, raw_path: Path):
        self.raw_path = Path(raw_path)
        self.raw_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> int:
        lock_path = self.raw_path.with_name(self.raw_path.name + ".lock")
        with lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                cursor = 0
                while True:
                    batch = self.fetch(cursor, 1000)
                    for offset, item in batch:
                        if _key(item) == _key(record) and item == record:
                            return offset
                    if len(batch) < 1000:
                        break
                    cursor += len(batch)
                if self.raw_path.exists():
                    with self.raw_path.open(encoding="utf-8") as stream:
                        cursor = sum(1 for _ in stream)
                else:
                    cursor = 0
                with self.raw_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                return cursor
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def fetch(self, cursor: int = 0, limit: int = 100) -> list[tuple[int, dict[str, Any]]]:
        if cursor < 0 or limit < 1 or limit > 1000:
            raise ValueError("cursor must be non-negative and limit must be between 1 and 1000")
        if not self.raw_path.exists():
            return []
        result = []
        with self.raw_path.open(encoding="utf-8") as stream:
            for offset, line in enumerate(stream):
                if offset >= cursor and len(result) < limit:
                    result.append((offset, json.loads(line)))
        return result


class OrbitDBProvider(Provider):
    """Runtime-only adapter for the reference registryd Unix-socket contract.

    OrbitDB/Helia remain transport concerns. Validation, authority, receipts,
    and reconciliation stay in ``Runtime`` or the external controller.
    """

    def __init__(self, socket_path: Path, stream: str, *, token: str | None = None,
                 timeout: float = 30.0,
                 encode: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
                 decode: Callable[[dict[str, Any]], dict[str, Any]] | None = None):
        if not isinstance(stream, str) or not stream or len(stream) > 64:
            raise ValueError("stream must be a non-empty string of at most 64 characters")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.socket_path = Path(socket_path)
        self.stream = stream
        self.token = token
        self.timeout = timeout
        self.encode = encode or (lambda record: record)
        self.decode = decode or (lambda record: record)
        self.next_cursor: ProviderCursor | None = None

    def _request(self, request: dict[str, Any]) -> dict[str, Any]:
        request = dict(request)
        if self.token is not None:
            request["token"] = self.token
        payload = (json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        deadline = time.monotonic() + self.timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(str(self.socket_path))
            connection.sendall(payload)
            response = bytearray()
            while not response.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("OrbitDB provider request timed out")
                connection.settimeout(remaining)
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > 1024 * 1024:
                    raise ValueError("OrbitDB provider response exceeds 1 MiB")
        try:
            value = json.loads(response.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("OrbitDB provider returned malformed JSON") from error
        if not isinstance(value, dict) or value.get("ok") is not True:
            error = value.get("error") if isinstance(value, dict) else None
            code = error.get("code") if isinstance(error, dict) else "transport_error"
            raise RuntimeError(f"OrbitDB provider request failed: {code}")
        return value

    def append(self, record: dict[str, Any]) -> ProviderCursor:
        response = self._request({"operation": "append", "stream": self.stream, "event": self.encode(record)})
        result = response.get("cursor")
        if not isinstance(result, str) or not re.fullmatch(r"v1:(0|[1-9][0-9]*)", result):
            raise ValueError("OrbitDB provider append response has no valid cursor")
        return result

    def fetch(self, cursor: ProviderCursor = 0, limit: int = 100) -> list[tuple[ProviderCursor, dict[str, Any]]]:
        if isinstance(cursor, int):
            if cursor < 0:
                raise ValueError("cursor must be non-negative")
            cursor = f"v1:{cursor}"
        elif not isinstance(cursor, str):
            raise ValueError("cursor must be an integer or opaque string")
        elif not cursor or len(cursor) > 1024:
            raise ValueError("cursor must be a non-empty bounded string")
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        response = self._request({"operation": "list", "stream": self.stream, "limit": limit, "cursor": cursor})
        records = response.get("records")
        if not isinstance(records, list):
            raise ValueError("OrbitDB provider list response has no records")
        next_cursor = response.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 1024:
            raise ValueError("OrbitDB provider list response has no next cursor")
        if next_cursor.startswith("v1:") and re.fullmatch(r"v1:(0|[1-9][0-9]*)", next_cursor) is None:
            raise ValueError("OrbitDB provider list response has malformed next cursor")
        self.next_cursor = next_cursor
        result = []
        previous_sequence: int | None = None
        requested_sequence = int(cursor[3:]) if re.fullmatch(r"v1:(0|[1-9][0-9]*)", cursor) else None
        for item in records:
            if not isinstance(item, dict) or not isinstance(item.get("hash"), str) or not isinstance(item.get("event"), dict):
                raise ValueError("OrbitDB provider list response contains a malformed record")
            cursor = item.get("sequence", item["hash"])
            if not isinstance(cursor, (int, str)) or isinstance(cursor, bool):
                raise ValueError("OrbitDB provider list response contains a malformed cursor")
            if isinstance(cursor, int):
                if cursor < 0 or (requested_sequence is not None and cursor < requested_sequence):
                    raise ValueError("OrbitDB provider list response contains an out-of-range cursor")
                if previous_sequence is not None and cursor <= previous_sequence:
                    raise ValueError("OrbitDB provider list response cursors are not strictly increasing")
                previous_sequence = cursor
            elif not cursor or len(cursor) > 1024:
                raise ValueError("OrbitDB provider list response contains an invalid opaque cursor")
            result.append((cursor, self.decode(item["event"])))
        if previous_sequence is not None and next_cursor.startswith("v1:") and int(next_cursor[3:]) <= previous_sequence:
            raise ValueError("OrbitDB provider list response next cursor does not advance")
        return result


class Runtime:
    """Ingest envelopes, retain quarantine, and rebuild a deterministic projection."""

    def __init__(self, state_dir: Path, provider: Provider, public_keys: dict[str, str], max_bytes: int = 131072):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.provider = provider
        self.public_keys = dict(public_keys)
        self.max_bytes = max_bytes
        self.db = sqlite3.connect(self.state_dir / "registry.sqlite3", timeout=30)
        self.db.execute("PRAGMA busy_timeout = 30000")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS records (
            record_key TEXT PRIMARY KEY, record_id TEXT, generation INTEGER,
            predecessor TEXT, status TEXT NOT NULL, reason TEXT, envelope TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS projection (
            record_id TEXT PRIMARY KEY, schema TEXT NOT NULL, payload TEXT NOT NULL, generation INTEGER NOT NULL
          );
        """)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _validate(self, record: dict[str, Any]) -> tuple[str, str | None]:
        required = ("protocolEpoch", "wireVersion", "schemaVersion", "recordId", "recordVersion",
                    "generation", "predecessor", "schema", "payload", "issuer", "signature")
        if not isinstance(record, dict) or any(name not in record for name in required):
            return "quarantined", "malformed-record"
        integer_fields = ("protocolEpoch", "wireVersion", "schemaVersion", "recordVersion", "generation")
        if any(isinstance(record[name], bool) or not isinstance(record[name], int) for name in integer_fields):
            return "quarantined", "malformed-record"
        if (not isinstance(record["recordId"], str) or not isinstance(record["schema"], str)
                or not isinstance(record["payload"], dict) or record["generation"] < 1
                or not isinstance(record["predecessor"], (str, type(None)))
                or not isinstance(record["issuer"], str) or not isinstance(record["signature"], str)):
            return "quarantined", "malformed-record"
        if record["schema"] not in SCHEMAS:
            return "quarantined", "unknown-schema" if record.get("schema") not in SCHEMAS else "malformed-record"
        if record["schemaVersion"] != 1:
            return "quarantined", "unsupported-schema-version"
        if record["protocolEpoch"] != 1:
            return "quarantined", "unknown-epoch"
        if record["wireVersion"] != 1:
            return "quarantined", "unsupported-wire-version"
        features = record.get("requiredFeatures", [])
        if (not isinstance(features, list) or any(not isinstance(feature, str) for feature in features)):
            return "quarantined", "malformed-record"
        if features:
            return "quarantined", "unsupported-required-feature"
        try:
            encoded = canonical_json(record)
            unsigned = canonical_json(_without_signature(record))
        except (TypeError, ValueError):
            return "quarantined", "malformed-record"
        if len(encoded) > self.max_bytes:
            return "quarantined", "framing-limit"
        def unsafe(value: Any) -> bool:
            if isinstance(value, str):
                return (
                    value.startswith(("/nix/store/", "/run/secrets/", "-----BEGIN"))
                    or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\s]+:[^/?#\s]+@", value) is not None
                    or re.match(r"^Bearer\s+\S+$", value, re.IGNORECASE) is not None
                )
            if isinstance(value, dict):
                return any(unsafe(key) or unsafe(item) for key, item in value.items())
            if isinstance(value, list):
                return any(unsafe(item) for item in value)
            return False
        if unsafe(_without_signature(record)):
            return "quarantined", "unsafe-value"
        try:
            verify = VerifyKey(_unb64(self.public_keys[record["issuer"]]))
            verify.verify(unsigned, _unb64(record["signature"]))
        except (KeyError, ValueError, TypeError, binascii.Error, BadSignatureError):
            return "quarantined", "invalid-signature"
        return "accepted", None

    def ingest(self, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        outcomes = []
        for record in records:
            if isinstance(record, dict) and "recordId" in record and "recordVersion" in record:
                record_key = _key(record)
            else:
                try:
                    record_key = "malformed:" + _digest(record)
                except (TypeError, ValueError):
                    record_key = "malformed:unserializable"
            status, reason = self._validate(record)
            try:
                envelope = canonical_json(record).decode()
            except (TypeError, ValueError):
                envelope = json.dumps({"malformed": repr(record)}, sort_keys=True)
            exact = self.db.execute("SELECT record_key, status FROM records WHERE envelope = ?", (envelope,)).fetchone()
            existing = self.db.execute("SELECT envelope, status FROM records WHERE record_key = ?", (record_key,)).fetchone()
            if exact:
                record_key = exact[0]
                status, reason = exact[1], None
            else:
                if existing:
                    record_key = f"{record_key}#conflict:{hashlib.sha256(envelope.encode()).hexdigest()}"
                self.provider.append(record)
                self.db.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (record_key, record.get("recordId"), record.get("generation"), record.get("predecessor"),
                     status, reason, envelope))
            outcomes.append({"recordKey": record_key, "status": status, "reason": reason})
        self.db.commit()
        self._reconcile()
        self._materialize()
        for outcome in outcomes:
            row = self.db.execute("SELECT status, reason FROM records WHERE record_key = ?", (outcome["recordKey"],)).fetchone()
            if row:
                outcome["status"], outcome["reason"] = row
        return outcomes

    def _reconcile(self) -> None:
        rows = self.db.execute("SELECT rowid, record_key, record_id, generation, predecessor, envelope FROM records").fetchall()
        records = [(rowid, record_key, json.loads(raw)) for rowid, record_key, _, _, _, raw in rows]
        by_key: dict[str, list[tuple[int, str, dict[str, Any]]]] = {}
        for rowid, record_key, record in records:
            base_key = _key(record) if isinstance(record, dict) else record_key
            by_key.setdefault(base_key, []).append((rowid, record_key, record))
        reasons: dict[int, str | None] = {}
        valid = []
        for rowid, record_key, record in records:
            status, reason = self._validate(record)
            reasons[rowid] = reason
            if status == "accepted":
                valid.append((rowid, record_key, record))
        for entries in by_key.values():
            if len({canonical_json(item[2]) for item in entries}) > 1:
                for rowid, _, _ in entries:
                    reasons[rowid] = "conflicting-record-key"
        candidates = [entry for entry in valid if reasons[entry[0]] is None]
        by_id: dict[str, list[dict[str, Any]]] = {}
        for _, _, record in candidates:
            by_id.setdefault(record["recordId"], []).append(record)
        max_generation = {record_id: max(item["generation"] for item in items) for record_id, items in by_id.items()}
        for rowid, _, record in candidates:
            if record["generation"] < max_generation[record["recordId"]]:
                reasons[rowid] = "anti-rollback"
        successors: dict[str, set[tuple[str, int]]] = {}
        for _, _, record in candidates:
            if record["predecessor"] is not None:
                successors.setdefault(record["predecessor"], set()).add((record["recordId"], record["generation"]))
        for rowid, _, record in candidates:
            if record["predecessor"] is not None and len(successors.get(record["predecessor"], set())) > 1:
                reasons[rowid] = "forked-lineage"
        # Historical predecessors remain usable for continuity even when they
        # are no longer current state (anti-rollback). They are not exposed as
        # accepted records or projected state below.
        available = {(record["recordId"], record["generation"]) for rowid, _, record in candidates
                     if reasons[rowid] not in {"conflicting-record-key", "forked-lineage"}}
        for rowid, _, record in candidates:
            if reasons[rowid] is not None:
                continue
            predecessor = record["predecessor"]
            if not ((record["generation"] == 1 and predecessor is None)
                    or (predecessor, record["generation"] - 1) in available):
                reasons[rowid] = "missing-predecessor"
        with self.db:
            for rowid, _, _, _, _, _ in rows:
                status = "accepted" if reasons[rowid] is None else "quarantined"
                self.db.execute("UPDATE records SET status = ?, reason = ? WHERE rowid = ?", (status, reasons[rowid], rowid))

    def _materialize(self) -> None:
        accepted = self.db.execute("SELECT record_key, record_id, generation, predecessor, status, reason, envelope FROM records WHERE status = 'accepted' OR reason = 'anti-rollback' ORDER BY generation, record_key").fetchall()
        available: dict[str, dict[str, Any]] = {}
        available_ids: set[str] = set()
        accepted_keys = {record_key for record_key, _, _, _, status, _, _ in accepted if status == "accepted"}
        for record_key, record_id, generation, predecessor, _, _, raw in accepted:
            if (generation == 1 and predecessor is None) or predecessor in available_ids:
                record = json.loads(raw)
                available[_key(record)] = record
                available_ids.add(record["recordId"])
        latest: dict[str, tuple[int, dict[str, Any]]] = {}
        for record in available.values():
            if _key(record) not in accepted_keys:
                continue
            current = latest.get(record["recordId"])
            if current is None or record["generation"] >= current[0]:
                latest[record["recordId"]] = (record["generation"], record)
        with self.db:
            self.db.execute("DELETE FROM projection")
            self.db.executemany("INSERT INTO projection VALUES (?, ?, ?, ?)",
                [(record_id, record["schema"], json.dumps(record["payload"], sort_keys=True), generation)
                 for record_id, (generation, record) in latest.items()])

    def accepted(self, cursor: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000 or cursor < 0:
            raise ValueError("cursor must be non-negative and limit must be between 1 and 1000")
        rows = self.db.execute("SELECT envelope FROM records WHERE status = 'accepted' ORDER BY rowid LIMIT ? OFFSET ?", (limit, cursor)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def quarantine(self) -> list[dict[str, Any]]:
        return [{"record": json.loads(raw), "reason": reason} for raw, reason in self.db.execute("SELECT envelope, reason FROM records WHERE status = 'quarantined' ORDER BY rowid")]

    def projection(self) -> dict[str, dict[str, Any]]:
        return {record_id: {"schema": schema, "payload": json.loads(payload), "generation": generation}
                for record_id, schema, payload, generation in self.db.execute("SELECT record_id, schema, payload, generation FROM projection")}
