"""Durable record ingestion; private keys and public state have separate roots."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


SCHEMAS = frozenset({"node-identity", "relationship", "capability", "service", "endpoint"})


def canonical_json(value: Any) -> bytes:
    """The wire canonical form: UTF-8, sorted keys, no insignificant whitespace."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _without_signature(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "signature"}


def _key(record: dict[str, Any]) -> str:
    return f"{record.get('recordId')}:{record.get('recordVersion')}"


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


def generate_keypair(key_dir: Path, issuer: str) -> RuntimeKey:
    """Create a runtime-only private key and its public verification key."""
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = RuntimeKey(issuer, SigningKey.generate())
    private_path = key_dir / f"{issuer}.private"
    private_path.write_text(_b64(bytes(key.signing_key)))
    os.chmod(private_path, 0o600)
    (key_dir / f"{issuer}.public").write_text(key.public_key + "\n")
    return key


class Provider(ABC):
    @abstractmethod
    def append(self, record: dict[str, Any]) -> int: ...

    @abstractmethod
    def fetch(self, cursor: int = 0, limit: int = 100) -> list[tuple[int, dict[str, Any]]]: ...


class FileProvider(Provider):
    """Append-only JSONL transport. Cursors are line offsets, never timestamps."""

    def __init__(self, raw_path: Path):
        self.raw_path = Path(raw_path)
        self.raw_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> int:
        cursor = 0
        while True:
            batch = self.fetch(cursor, 1000)
            for offset, item in batch:
                if _key(item) == _key(record):
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
        return cursor

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


class Runtime:
    """Ingest envelopes, retain quarantine, and rebuild a deterministic projection."""

    def __init__(self, state_dir: Path, provider: Provider, public_keys: dict[str, str], max_bytes: int = 131072):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.provider = provider
        self.public_keys = dict(public_keys)
        self.max_bytes = max_bytes
        self.db = sqlite3.connect(self.state_dir / "registry.sqlite3")
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
        required = ("recordId", "recordVersion", "generation", "schema", "schemaVersion", "payload", "issuer", "signature")
        if not isinstance(record, dict) or any(name not in record for name in required):
            return "quarantined", "malformed-record"
        if not isinstance(record["recordId"], str) or not isinstance(record["recordVersion"], int) or not isinstance(record["generation"], int):
            return "quarantined", "malformed-record"
        if not isinstance(record["payload"], dict) or record["schema"] not in SCHEMAS:
            return "quarantined", "unknown-schema" if record.get("schema") not in SCHEMAS else "malformed-record"
        if len(canonical_json(record)) > self.max_bytes:
            return "quarantined", "framing-limit"
        try:
            verify = VerifyKey(_unb64(self.public_keys[record["issuer"]]))
            verify.verify(canonical_json(_without_signature(record)), _unb64(record["signature"]))
        except (KeyError, ValueError, BadSignatureError):
            return "quarantined", "invalid-signature"
        return "accepted", None

    def ingest(self, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        outcomes = []
        for record in records:
            record_key = _key(record)
            status, reason = self._validate(record)
            existing = self.db.execute("SELECT envelope, status FROM records WHERE record_key = ?", (record_key,)).fetchone()
            if existing:
                status, reason = existing[1], None
            else:
                self.provider.append(record)
                self.db.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (record_key, record.get("recordId"), record.get("generation"), record.get("predecessor"),
                     status, reason, canonical_json(record).decode()))
            outcomes.append({"recordKey": record_key, "status": status, "reason": reason})
        self.db.commit()
        self._materialize()
        return outcomes

    def _materialize(self) -> None:
        accepted = self.db.execute("SELECT record_id, generation, predecessor, envelope FROM records WHERE status = 'accepted' ORDER BY generation, record_key").fetchall()
        available: dict[str, dict[str, Any]] = {}
        available_ids: set[str] = set()
        for record_id, generation, predecessor, raw in accepted:
            if (generation == 1 and predecessor is None) or predecessor in available_ids:
                record = json.loads(raw)
                available[_key(record)] = record
                available_ids.add(record["recordId"])
        latest: dict[str, tuple[int, dict[str, Any]]] = {}
        for record in available.values():
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
