"""Bilateral, non-delegating parent relationships between existing local roots."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .runtime import PAIR_PROTOCOL as PROTOCOL, Runtime, RuntimeKey, _b64, _digest, _unb64, canonical_json, load_keypair

LIFETIME = 300

_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
_DOMAIN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_DIGEST = r"[0-9a-f]{64}"


def _text(value, pattern):
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError("invalid pairing field")
    return value


def _fields(value, *keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("invalid pairing object")


def _binary(value, length):
    _text(value, r"[A-Za-z0-9_-]{%d}" % ((length * 8 + 5) // 6))
    decoded = _unb64(value)
    if len(decoded) != length or _b64(decoded) != value:
        raise ValueError("noncanonical encoding")
    return decoded


def descriptor(value):
    _fields(value, "identity", "domain", "publicKey", "genesisDigest")
    _text(value["identity"], _NAME)
    _text(value["domain"], _DOMAIN)
    _text(value["genesisDigest"], _DIGEST)
    _binary(value["publicKey"], 32)
    return value


def _sign(key, kind, **fields):
    unsigned = {"type": PROTOCOL + kind, **fields}
    return {**unsigned, "signature": key.sign(unsigned)}


def _verify(value, kind, owner):
    if value["type"] != PROTOCOL + kind:
        raise ValueError("wrong pairing message")
    try:
        VerifyKey(_binary(owner["publicKey"], 32)).verify(
            canonical_json({k: v for k, v in value.items() if k != "signature"}),
            _binary(value["signature"], 64),
        )
    except BadSignatureError as error:
        raise ValueError("invalid pairing signature") from error


def _endpoints(parent, child):
    descriptor(parent)
    descriptor(child)
    if (parent["domain"] != child["domain"] or parent["identity"] == child["identity"]
            or parent["publicKey"] == child["publicKey"]):
        raise ValueError("incompatible pairing endpoints")


def _request(value, session=None):
    _fields(value, "type", "parent", "child", "session", "expires", "signature")
    _endpoints(value["parent"], value["child"])
    _text(value["session"], _DIGEST)
    if type(value["expires"]) is not int or value["expires"] <= 0:
        raise ValueError("invalid request expiry")
    if session is not None:
        if _text(session, _DIGEST) != value["session"]:
            raise ValueError("wrong pairing session")
        now = int(time.time())
        if not now < value["expires"] <= now + LIFETIME:
            raise ValueError("expired or future request")
    _verify(value, "request", value["child"])
    return value


def _approval(value, session=None):
    _fields(value, "type", "request", "signature")
    req = _request(value["request"], session)
    _verify(value, "approve", req["parent"])
    return req


def _relationship(req):
    parent, child = req["parent"], req["child"]
    return {
        "protocolEpoch": 1, "wireVersion": 1, "schemaVersion": 1, "recordVersion": 1,
        "generation": 1, "predecessor": None, "schema": "relationship",
        "recordId": f"existing-root-parent:{parent['identity']}:{child['identity']}",
        "issuer": child["identity"],
        "payload": {"from": parent["identity"], "to": child["identity"], "kind": "parent",
                    "status": "active", "domain": child["domain"], "pairingProtocol": PROTOCOL},
    }


def _certificate(value):
    if not isinstance(value, dict):
        raise ValueError("invalid pairing certificate")
    req = _approval(value.get("approval"))
    envelope = _relationship(req)
    _fields(value, *envelope, "type", "signature", "approval", "acceptedAt")
    # Compare canonical bytes to distinguish booleans from protocol integers.
    if canonical_json({k: value[k] for k in envelope}) != canonical_json(envelope):
        raise ValueError("relationship differs from signed request")
    if (type(value["acceptedAt"]) is not int
            or not req["expires"] - LIFETIME <= value["acceptedAt"] < req["expires"]):
        raise ValueError("acceptance outside request lifetime")
    _verify(value, "accept", req["child"])
    return req


class Pairing:
    """All calls run under the RegistryServer runtime lock on its SQLite connection."""

    def __init__(self, runtime: Runtime, key_dir):
        self.runtime = runtime
        self.db = runtime.db
        self.key_dir = key_dir

    def _local(self) -> tuple[dict, RuntimeKey]:
        roots = self.runtime.local_authorities
        if len(roots) != 1:
            raise ValueError("one existing local root is required")
        name, (domain, public) = next(iter(roots.items()))
        summary = self.runtime.state_summary(name)["localIdentity"]
        key = load_keypair(self.key_dir, name)
        if (not summary["selfRooted"] or summary["conflict"] or summary["generation"] != 1
                or key is None or key.public_key != public):
            raise ValueError("a current self-rooted genesis key is required")
        digest, = self.db.execute("SELECT record_digest FROM local_genesis WHERE identity=?", (name,)).fetchone()
        return descriptor({"identity": name, "domain": domain, "publicKey": public,
                           "genesisDigest": digest}), key

    def _check_direction(self, parent, child):
        _endpoints(parent, child)
        source, target = parent["identity"], child["identity"]
        # Pending approvals fix the same direction and keys across interruptions.
        for parent_json, child_json in self.db.execute("SELECT parent,child FROM parent_pairs"):
            previous = (json.loads(parent_json), json.loads(child_json))
            for old in previous:
                for new in (parent, child):
                    if ((old["identity"] == new["identity"] or old["publicKey"] == new["publicKey"])
                            and old != new):
                        raise ValueError("inconsistent identity in pairing history")
            if previous == (child, parent):
                raise ValueError("opposite pairing direction already reserved")
        for endpoint in (parent, child):
            known = self.runtime.public_keys
            if (endpoint["identity"] in known and known[endpoint["identity"]] != endpoint["publicKey"]
                    or any(k != endpoint["identity"] and v == endpoint["publicKey"] for k, v in known.items())):
                raise ValueError("pairing conflicts with an existing Registry key")
        adjacency = {}
        for record in self.runtime.projection().values():
            p = record["payload"]
            if record["schema"] in {"node-identity", "identity-generation"}:
                identity, public = p.get("identity"), p.get("publicKey")
                for endpoint in (parent, child):
                    if ((identity == endpoint["identity"] and public and public != endpoint["publicKey"])
                            or (public == endpoint["publicKey"] and identity != endpoint["identity"])):
                        raise ValueError("pairing conflicts with an established identity")
            if (record["schema"] == "relationship" and p.get("kind") == "parent"
                    and p.get("status") == "active" and p.get("domain", parent["domain"]) == parent["domain"]
                    and isinstance(p.get("from"), str) and isinstance(p.get("to"), str)):
                if (p["from"], p["to"]) == (source, target) and p.get("pairingProtocol") != PROTOCOL:
                    raise ValueError("relationship already managed by another protocol")
                adjacency.setdefault(p["from"], set()).add(p["to"])
        todo, seen = [target], set()
        while todo:
            node = todo.pop()
            if node == source:
                raise ValueError("pairing would form a parent cycle")
            if node not in seen:
                seen.add(node)
                todo.extend(adjacency.get(node, ()))

    def status(self, parent, child):
        _text(parent, _NAME)
        _text(child, _NAME)
        row = self.db.execute(
            "SELECT digest,record_id FROM parent_pairs WHERE parent_name=? AND child_name=?",
            (parent, child),
        ).fetchone()
        if row and row[0]:
            for (raw,) in self.db.execute(
                "SELECT r.envelope FROM records r JOIN projection p ON p.record_id=r.record_id "
                "WHERE r.record_id=? AND r.status='accepted' AND r.generation=p.generation",
                (row[1],),
            ):
                cert = json.loads(raw)
                if _digest(cert) == row[0]:
                    return {"paired": True, "digest": row[0], "certificate": cert}
            raise ValueError("stored pairing is no longer projected")
        return {"paired": False, "digest": None, "certificate": None}

    def _reserve(self, req):
        parent, child = req["parent"], req["child"]
        record_id = _relationship(req)["recordId"]
        if self.db.execute("SELECT 1 FROM projection WHERE record_id=?", (record_id,)).fetchone():
            raise ValueError("relationship identifier already in use")
        self.db.execute(
            "INSERT INTO parent_pairs(parent_name,child_name,parent,child,record_id) VALUES(?,?,?,?,?) "
            "ON CONFLICT(parent_name,child_name) DO NOTHING",
            (parent["identity"], child["identity"], canonical_json(parent).decode(),
             canonical_json(child).decode(), record_id),
        )

    def _store(self, cert, req, *, child_side):
        parent, child = req["parent"], req["child"]
        names = (parent["identity"], child["identity"])
        known = self.status(*names)
        if known["paired"]:
            if known["digest"] != _digest(cert):
                raise ValueError("different certificate already committed")
            return known
        with self.db:
            if child_side:
                self._reserve(req)
            cursor = self.db.execute(
                "UPDATE parent_pairs SET digest=? WHERE parent_name=? AND child_name=? AND digest IS NULL",
                (_digest(cert), *names),
            )
            if cursor.rowcount != 1:
                raise ValueError("parent has no local approval")
            # Never upload the interactive protocol to the untrusted retention provider.
            self.runtime.ingest([cert], retain=False, commit=False)
            result = self.status(*names)
        return result

    def handle(self, op: str, data: dict[str, Any]):
        if op == "status":
            _fields(data, "parent", "child")
            return self.status(data["parent"], data["child"])
        local, key = self._local()
        if op == "identity":
            _fields(data)
            return local
        if op == "request":
            _fields(data, "parent", "session")
            parent = descriptor(data["parent"])
            session = _text(data["session"], _DIGEST)
            self._check_direction(parent, local)
            if self.status(parent["identity"], local["identity"])["paired"]:
                raise ValueError("use the existing pairing certificate")
            return _sign(key, "request", parent=parent, child=local, session=session,
                         expires=int(time.time()) + LIFETIME)
        if op in {"approve", "accept"}:
            field = "request" if op == "approve" else "approval"
            _fields(data, field, "session")
            session = _text(data["session"], _DIGEST)
            req = (_request if op == "approve" else _approval)(data[field], session)
            parent, child = req["parent"], req["child"]
            if local != (parent if op == "approve" else child):
                raise ValueError("wrong local pairing role")
            self._check_direction(parent, child)
            if self.status(parent["identity"], child["identity"])["paired"]:
                raise ValueError("use the existing pairing certificate")
            if op == "approve":
                with self.db:
                    self._reserve(req)
                return _sign(key, "approve", request=req)
            cert = _sign(key, "accept", approval=data[field], acceptedAt=int(time.time()), **_relationship(req))
            _certificate(cert)
            return self._store(cert, req, child_side=True)["certificate"]
        if op == "commit":
            _fields(data, "certificate")
            cert = data["certificate"]
            req = _certificate(cert)
            if req["parent"] != local:
                raise ValueError("wrong local pairing role")
            self._check_direction(req["parent"], req["child"])
            return self._store(cert, req, child_side=False)
        raise ValueError("unknown pairing operation")
