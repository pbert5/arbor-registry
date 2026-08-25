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


SCHEMAS = frozenset({
    "node-identity", "identity-generation", "relationship", "capability", "service", "endpoint",
    "enrollment", "revocation", "recovery-authorization", "receipt",
})
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


def make_enrollment_request(
    identity_key: RuntimeKey,
    node_id: str,
    *,
    platform: str,
    requested_parent: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Create a self-signed enrollment request using runtime-held identity.

    The request is not authority.  It only proves possession of the proposed
    node key; an existing authority must approve it before a node-identity
    record can enter accepted state.
    """
    if not isinstance(node_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
        raise ValueError("node_id is invalid")
    if not isinstance(platform, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", platform):
        raise ValueError("platform is invalid")
    if requested_parent is not None and not isinstance(requested_parent, str):
        raise ValueError("requested_parent is invalid")
    if nonce is None:
        nonce = _b64(os.urandom(24))
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", nonce):
        raise ValueError("nonce is invalid")
    unsigned = {
        "kind": "arbor-enrollment-request",
        "version": 1,
        "nodeId": node_id,
        "generation": 1,
        "platform": platform,
        "publicKey": identity_key.public_key,
        "requestedParent": requested_parent,
        "nonce": nonce,
        "subject": identity_key.issuer,
    }
    return {**unsigned, "signature": identity_key.sign(unsigned)}


def approve_enrollment(
    request: dict[str, Any],
    authority_key: RuntimeKey,
    *,
    authority_root: str | None = None,
    relationship_scope: str = "dependent",
) -> dict[str, Any]:
    """Turn a valid self-signed request into an authority-signed identity record."""
    if not isinstance(request, dict) or request.get("kind") != "arbor-enrollment-request" or request.get("version") != 1:
        raise ValueError("invalid enrollment request")
    required = ("nodeId", "generation", "platform", "publicKey", "nonce", "signature")
    if any(field not in request for field in required):
        raise ValueError("incomplete enrollment request")
    try:
        VerifyKey(_unb64(request["publicKey"])).verify(
            canonical_json({key: value for key, value in request.items() if key != "signature"}),
            _unb64(request["signature"]),
        )
    except (ValueError, TypeError, binascii.Error, BadSignatureError) as error:
        raise ValueError("enrollment request signature is invalid") from error
    if not isinstance(request["nodeId"], str) or not isinstance(request["platform"], str):
        raise ValueError("enrollment request fields are invalid")
    if relationship_scope not in {"dependent", "independent"}:
        raise ValueError("relationship scope is invalid")
    payload = {
        "identity": request["nodeId"],
        "publicKey": request["publicKey"],
        "platform": request["platform"],
        "requestedParent": request.get("requestedParent"),
        "relationshipScope": relationship_scope,
        "enrollmentRequestDigest": _digest(request),
        "approvedBy": authority_key.issuer,
        "authorityRoot": authority_root or authority_key.issuer,
    }
    unsigned = {
        "protocolEpoch": 1,
        "wireVersion": 1,
        "schemaVersion": 1,
        "recordVersion": 1,
        "recordId": request["nodeId"],
        "generation": 1,
        "predecessor": None,
        "issuer": authority_key.issuer,
        "schema": "node-identity",
        "payload": payload,
    }
    return {**unsigned, "signature": authority_key.sign(unsigned)}


def make_lifecycle_record(
    issuer_key: RuntimeKey,
    schema: str,
    record_id: str,
    payload: dict[str, Any],
    *,
    generation: int = 1,
    predecessor: str | None = None,
    record_version: int = 1,
) -> dict[str, Any]:
    """Create a signed record in one of the accepted lifecycle families."""
    if schema not in {"enrollment", "identity-generation", "revocation", "recovery-authorization", "receipt"}:
        raise ValueError("schema is not a lifecycle family")
    if not isinstance(record_id, str) or not record_id or not isinstance(payload, dict):
        raise ValueError("record id and payload are required")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ValueError("generation must be a positive integer")
    unsigned = {
        "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1, "recordVersion": record_version,
        "recordId": record_id, "generation": generation, "predecessor": predecessor,
        "issuer": issuer_key.issuer, "schema": schema, "payload": payload,
    }
    return {**unsigned, "signature": issuer_key.sign(unsigned)}


def make_recovery_approval(
    approver_key: RuntimeKey,
    identity: str,
    lost_generation: int,
    *,
    role: str,
    approver_generation: int,
    operation: str = "recovery",
    decision: str = "approve",
) -> dict[str, Any]:
    """Create the signed, generation-bound approval used by recovery."""
    if (not isinstance(identity, str) or not identity or isinstance(lost_generation, bool)
            or not isinstance(lost_generation, int) or lost_generation < 1
            or role not in {"operator", "parent", "peer"}
            or isinstance(approver_generation, bool) or not isinstance(approver_generation, int)
            or approver_generation < 1 or operation != "recovery"
            or decision != "approve"):
        raise ValueError("invalid recovery approval")
    unsigned = {
        "approver": approver_key.issuer,
        "role": role,
        "subject": identity,
        "generation": lost_generation,
        "operation": operation,
        "approverGeneration": approver_generation,
        "decision": decision,
    }
    return {**unsigned, "issuer": approver_key.issuer, "signature": approver_key.sign(unsigned)}


def make_recovery_authorization(
    authority_key: RuntimeKey,
    identity: str,
    lost_generation: int,
    new_public_key: str,
    approvals: list[dict[str, Any]],
    *,
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an authority-signed recovery authorization transaction."""
    if not isinstance(new_public_key, str) or not isinstance(approvals, list) or not approvals:
        raise ValueError("recovery authorization is incomplete")
    payload = {
        "identity": identity,
        "lostGeneration": lost_generation,
        "newGeneration": lost_generation + 1,
        "newPublicKey": new_public_key,
        "approvals": approvals,
        "provenance": provenance or [],
    }
    unsigned = {
        "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1, "recordVersion": 1,
        "recordId": f"{identity}:recovery:{lost_generation}", "generation": 1,
        "predecessor": None, "issuer": authority_key.issuer,
        "schema": "recovery-authorization", "payload": payload,
    }
    return {**unsigned, "signature": authority_key.sign(unsigned)}


def make_identity_generation(
    authority_key: RuntimeKey,
    identity: str,
    generation: int,
    public_key: str,
    *,
    predecessor: str | None = None,
    recovery_authorization: dict[str, Any] | None = None,
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create an authority-approved active identity generation record."""
    if not isinstance(identity, str) or not identity or generation < 1 or not isinstance(public_key, str):
        raise ValueError("identity generation is invalid")
    authorization_digest = _digest(recovery_authorization) if recovery_authorization is not None else None
    payload = {
        "identity": identity, "generation": generation, "publicKey": public_key,
        "status": "active", "recoveryAuthorizationDigest": authorization_digest,
        "provenance": provenance if provenance is not None else (
            recovery_authorization.get("payload", {}).get("provenance", [])
            if recovery_authorization is not None else []
        ),
    }
    return make_lifecycle_record(
        authority_key, "identity-generation", identity, payload,
        generation=generation, predecessor=predecessor, record_version=generation,
    )


def make_revocation(
    authority_key: RuntimeKey,
    identity: str,
    generation: int,
    reason: str,
    *,
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create an authority-signed revocation for one identity generation."""
    if not isinstance(identity, str) or generation < 1 or not isinstance(reason, str) or not reason:
        raise ValueError("revocation is invalid")
    return make_lifecycle_record(
        authority_key, "revocation", f"{identity}:revocation:{generation}",
        {"identity": identity, "generation": generation, "reason": reason, "provenance": provenance or []},
    )


def make_receipt(
    authority_key: RuntimeKey,
    subject: str,
    digest: str,
    *,
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a signed receipt anchoring a lifecycle transaction."""
    if not isinstance(subject, str) or not subject or not isinstance(digest, str) or not digest:
        raise ValueError("receipt is invalid")
    return make_lifecycle_record(
        authority_key, "receipt", f"receipt:{subject}:{digest}",
        {"subject": subject, "digest": digest, "provenance": provenance or []},
    )


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
        payload = record["payload"]
        if record["schema"] == "enrollment":
            if (not isinstance(payload.get("identity"), str) or not isinstance(payload.get("publicKey"), str)
                    or not isinstance(payload.get("requestDigest"), str)
                    or payload.get("approvedBy") != record["issuer"]):
                return "quarantined", "unapproved-enrollment"
        if record["schema"] == "identity-generation":
            if (not isinstance(payload.get("identity"), str) or not isinstance(payload.get("publicKey"), str)
                    or payload.get("generation") != record["generation"]
                    or payload.get("status", "active") not in {"active", "deprecated"}):
                return "quarantined", "malformed-identity-generation"
        if record["schema"] == "revocation":
            if (not isinstance(payload.get("identity"), str) or not isinstance(payload.get("generation"), int)
                    or payload["generation"] < 1 or not isinstance(payload.get("reason"), str)
                    or not payload["reason"]):
                return "quarantined", "malformed-revocation"
        if record["schema"] == "recovery-authorization":
            if self._recovery_approval_reason(payload) is not None:
                return "quarantined", self._recovery_approval_reason(payload)
        if record["schema"] == "receipt":
            if not isinstance(payload.get("subject"), str) or not isinstance(payload.get("digest"), str):
                return "quarantined", "malformed-receipt"
        return "accepted", None

    def _recovery_approval_reason(self, payload: dict[str, Any]) -> str | None:
        identity = payload.get("identity")
        lost = payload.get("lostGeneration")
        new = payload.get("newGeneration")
        approvals = payload.get("approvals")
        if (not isinstance(identity, str) or not isinstance(lost, int) or isinstance(lost, bool) or lost < 1
                or new != lost + 1 or not isinstance(payload.get("newPublicKey"), str)
                or not isinstance(approvals, list) or not approvals
                or not isinstance(payload.get("provenance", []), list)):
            return "malformed-recovery-authorization"
        for approval in approvals:
            if not isinstance(approval, dict) or any(key not in approval for key in (
                    "approver", "role", "subject", "generation", "operation", "approverGeneration", "decision", "signature")):
                return "invalid-recovery-approval"
            if approval.get("subject") != identity or approval.get("generation") != lost:
                return "unbound-recovery-approval"
            if (approval["subject"] != identity or approval["generation"] != lost
                    or approval["operation"] != "recovery" or approval["decision"] != "approve"
                    or approval["role"] not in {"operator", "parent", "peer"}
                    or not isinstance(approval["approverGeneration"], int)
                    or approval["approverGeneration"] < 1
                    or approval.get("approver") != approval.get("issuer")):
                return "unbound-recovery-approval"
            try:
                key = VerifyKey(_unb64(self.public_keys[approval["approver"]]))
                unsigned = {key: value for key, value in approval.items() if key not in {"signature", "issuer"}}
                key.verify(canonical_json(unsigned), _unb64(approval["signature"]))
            except (KeyError, ValueError, TypeError, binascii.Error, BadSignatureError):
                return "invalid-recovery-approval-signature"
        return None

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
            valid_entries = [item for item in entries if reasons[item[0]] is None]
            if len({canonical_json(item[2]) for item in valid_entries}) > 1:
                for rowid, _, _ in entries:
                    if reasons[rowid] is None:
                        reasons[rowid] = "conflicting-record-key"
        candidates = [entry for entry in valid if reasons[entry[0]] is None]
        # Lifecycle records form a small, signed state machine layered over
        # ordinary lineage.  A revocation is authoritative for every record
        # carrying the same identity/generation, including materialization.
        revocations = {
            (record["payload"]["identity"], record["payload"]["generation"])
            for _, _, record in candidates
            if record["schema"] == "revocation"
            and isinstance(record.get("payload"), dict)
            and isinstance(record["payload"].get("identity"), str)
            and isinstance(record["payload"].get("generation"), int)
        }
        authorizations = {
            (record["payload"]["identity"], record["payload"]["newGeneration"]): record
            for _, _, record in candidates
            if record["schema"] == "recovery-authorization"
            and isinstance(record.get("payload"), dict)
            and isinstance(record["payload"].get("identity"), str)
            and isinstance(record["payload"].get("newGeneration"), int)
        }
        active_generations = {
            record["payload"]["identity"]: max(record["payload"]["generation"] for _, _, record in candidates
                if record["schema"] == "identity-generation"
                and isinstance(record.get("payload"), dict)
                and isinstance(record["payload"].get("identity"), str)
                and isinstance(record["payload"].get("generation"), int)
                and record["payload"].get("status", "active") == "active")
            for identity in {record["payload"].get("identity") for _, _, record in candidates
                if record["schema"] == "identity-generation" and isinstance(record.get("payload"), dict)
                and isinstance(record["payload"].get("identity"), str)}
            for record in [next(record for _, _, record in candidates
                if record["schema"] == "identity-generation"
                and record["payload"].get("identity") == identity
                and record["payload"].get("generation") == max(item["payload"]["generation"] for _, _, item in candidates
                    if item["schema"] == "identity-generation" and item.get("payload", {}).get("identity") == identity))]
        }
        for rowid, _, record in candidates:
            payload = record.get("payload", {})
            identity = payload.get("identity") if isinstance(payload, dict) else None
            generation = payload.get("generation") if isinstance(payload, dict) else None
            if (identity, generation) in revocations and record["schema"] != "revocation":
                reasons[rowid] = "revoked-generation"
            if record["schema"] == "identity-generation":
                if payload.get("status", "active") != "active":
                    reasons[rowid] = "inactive-generation"
                if (identity, generation) in revocations:
                    reasons[rowid] = "revoked-generation"
            if record["schema"] == "node-identity" and isinstance(payload, dict):
                if payload.get("identityGeneration") is not None and (
                        identity, payload.get("identityGeneration")) in revocations:
                    reasons[rowid] = "revoked-generation"
            record_generation = payload.get("identityGeneration") if record["schema"] == "node-identity" else generation
            if isinstance(identity, str) and isinstance(record_generation, int) and identity in active_generations:
                if (reasons[rowid] is None and record_generation < active_generations[identity]
                        and record["schema"] not in {"revocation", "recovery-authorization"}):
                    reasons[rowid] = "stale-generation"
            if record["schema"] == "identity-generation" and generation > 1:
                authorization = authorizations.get((identity, generation))
                if authorization is None or authorization["payload"].get("lostGeneration") != generation - 1:
                    reasons[rowid] = "missing-recovery-authorization"
                else:
                    payload_digest = payload.get("recoveryAuthorizationDigest")
                    if payload_digest != _digest(authorization):
                        reasons[rowid] = "recovery-provenance-mismatch"
        by_id: dict[str, list[dict[str, Any]]] = {}
        for _, _, record in candidates:
            by_id.setdefault(record["recordId"], []).append(record)
        max_generation = {record_id: max(item["generation"] for item in items) for record_id, items in by_id.items()}
        for rowid, _, record in candidates:
            if reasons[rowid] is None and record["generation"] < max_generation[record["recordId"]]:
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
        available = {
            alias
            for rowid, _, record in candidates
            if reasons[rowid] not in {"conflicting-record-key", "forked-lineage"}
            for alias in ((record["recordId"], record["generation"]),
                          (f"{record['recordId']}:{record['generation']}", record["generation"]))
        }
        for rowid, _, record in candidates:
            if reasons[rowid] is not None:
                continue
            if record["schema"] in {"enrollment", "revocation", "recovery-authorization", "receipt"}:
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
        accepted = self.db.execute("SELECT record_key, record_id, generation, predecessor, status, reason, envelope FROM records WHERE status = 'accepted' OR reason IN ('anti-rollback', 'revoked-generation') ORDER BY generation, record_key").fetchall()
        available: dict[str, dict[str, Any]] = {}
        available_ids: set[str] = set()
        accepted_keys = {record_key for record_key, _, _, _, status, _, _ in accepted if status == "accepted"}
        for record_key, record_id, generation, predecessor, _, _, raw in accepted:
            if (generation == 1 and predecessor is None) or predecessor in available_ids:
                record = json.loads(raw)
                available[_key(record)] = record
                available_ids.add(record["recordId"])
                available_ids.add(f"{record['recordId']}:{record['generation']}")
        latest: dict[str, tuple[int, dict[str, Any]]] = {}
        for record in available.values():
            if _key(record) not in accepted_keys:
                continue
            if record["schema"] in {"enrollment", "revocation", "recovery-authorization", "receipt"}:
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
