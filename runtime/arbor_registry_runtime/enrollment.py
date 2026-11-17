"""Public file exchange for enrolling one new identity with a configured authority."""

import json
import re
import time

from .runtime import _digest, approve_enrollment, generate_keypair, load_keypair, make_enrollment_request

FIELDS = {
    "enrollment/status": {"authorityId"},
    "enrollment/request": {"nodeId", "platform", "authorityId"},
    "enrollment/approve": {"authorityId", "request", "requestDigest"},
    "enrollment/finish": {"nodeId", "approval"},
}
TTL = 900


def _match(value, pattern):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("invalid enrollment field")
    return value


def _identifier(value):
    return _match(value, r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _validate_request(request):
    if not isinstance(request, dict) or set(request) != {
        "kind", "version", "generation", "subject", "nodeId", "platform", "requestedParent",
        "publicKey", "signature", "nonce", "issuedAt", "expiresAt",
    }:
        raise ValueError("unexpected enrollment request")
    node = _identifier(request["nodeId"])
    authority = _identifier(request["requestedParent"])
    _match(request["platform"], r"[A-Za-z0-9._-]{1,128}")
    _match(request["publicKey"], r"[A-Za-z0-9_-]{43}")
    _match(request["signature"], r"[A-Za-z0-9_-]{86}")
    _match(request["nonce"], r"[A-Za-z0-9_-]{32}")
    if (node == authority or request["kind"] != "arbor-enrollment-request" or request["subject"] != node
            or any(type(request[k]) is not int or request[k] != 1 for k in ("version", "generation"))
            or type(request["issuedAt"]) is not int or type(request["expiresAt"]) is not int
            or request["expiresAt"] - request["issuedAt"] != TTL):
        raise ValueError("invalid enrollment request")


def _validate_approval(record):
    if not isinstance(record, dict) or set(record) != {
        "protocolEpoch", "wireVersion", "schemaVersion", "recordVersion", "recordId",
        "generation", "predecessor", "issuer", "schema", "payload", "signature",
    }:
        raise ValueError("unexpected enrollment approval")
    if (any(type(record[k]) is not int or record[k] != 1 for k in
            ("protocolEpoch", "wireVersion", "schemaVersion", "recordVersion", "generation"))
            or record["schema"] != "node-identity" or record["predecessor"] is not None):
        raise ValueError("invalid identity envelope")
    node, authority = _identifier(record["recordId"]), _identifier(record["issuer"])
    _match(record["signature"], r"[A-Za-z0-9_-]{86}")
    p = record["payload"]
    if not isinstance(p, dict) or set(p) != {
        "identity", "publicKey", "platform", "requestedParent", "relationshipScope",
        "enrollmentRequestDigest", "approvedBy", "authorityRoot",
    }:
        raise ValueError("unexpected identity payload")
    if (node == authority or p["identity"] != node or p["relationshipScope"] != "dependent"
            or any(p[k] != authority for k in ("requestedParent", "approvedBy", "authorityRoot"))):
        raise ValueError("incorrect approval identity or scope")
    _match(p["publicKey"], r"[A-Za-z0-9_-]{43}")
    _match(p["platform"], r"[A-Za-z0-9._-]{1,128}")
    _match(p["enrollmentRequestDigest"], r"[a-f0-9]{64}")


def validate_public_result(operation, result):
    """Whitelist the signed objects the adapter may export to Manager."""
    if operation == "enrollment/status":
        if (any(type(result.get(k)) is not bool for k in ("authorityTrusted", "canApprove"))
                or result.get("enrollmentState") not in {"new", "pending", "enrolled", "occupied", "self-rooted"}
                or (result.get("expiresAt") is not None and type(result["expiresAt"]) is not int)):
            raise ValueError("invalid enrollment status")
        _identifier(result["authorityId"])
        if result["joiningNodeId"] is not None:
            _identifier(result["joiningNodeId"])
        return {k: result[k] for k in ("authorityId", "authorityTrusted", "canApprove", "enrollmentState",
                                       "expiresAt", "joiningNodeId")}
    digest = _match(result.get("requestDigest"), r"[a-f0-9]{64}")
    safe = {"requestDigest": digest}
    if operation == "enrollment/request":
        request = result.get("request")
        _validate_request(request)
        if _digest(request) != digest:
            raise ValueError("incorrect request digest")
        safe["request"] = request
    if operation == "enrollment/approve":
        approval = result.get("approval")
        _validate_approval(approval)
        if approval["payload"]["enrollmentRequestDigest"] != digest:
            raise ValueError("incorrect approval digest")
        safe["approval"] = approval
    return safe


def _trusted(runtime, authority):
    if authority in runtime.local_authorities or authority not in runtime.authority_issuers:
        return False
    # This interface uses only a generation-one bootstrap signer. Any newer
    # lifecycle, accepted revocation, or conflicting signer closes admission.
    for status, envelope in _history(runtime, authority):
        record = json.loads(envelope)
        if runtime._validate(record)[0] != "accepted":
            continue
        schema, payload = record["schema"], record["payload"]
        if schema in {"identity-generation", "node-identity"} and (
                status != "accepted" or record["generation"] != 1 or payload.get("status") == "deprecated"
                or payload.get("publicKey") != runtime.public_keys[authority]):
            return False
        if schema in {"revocation", "recovery-authorization"} and status == "accepted":
            return False
    return True


def _external(runtime, authority):
    if not _trusted(runtime, authority):
        raise ValueError("external authority must be configured and current")


def _intent(runtime):
    return runtime.db.execute(
        "SELECT node, authority, platform, completed FROM manager_enrollment WHERE slot = 1"
    ).fetchone()


def _pending(runtime, digest=None):
    if digest is None:
        row = runtime.db.execute("SELECT request FROM manager_enrollment_requests ORDER BY rowid DESC LIMIT 1").fetchone()
    else:
        row = runtime.db.execute("SELECT request FROM manager_enrollment_requests WHERE digest = ?", (digest,)).fetchone()
    return json.loads(row[0]) if row else None


def _history(runtime, node):
    return runtime.db.execute(
        "SELECT status, envelope FROM records WHERE record_id = ? OR json_extract(envelope, '$.payload.identity') = ?",
        (node, node),
    ).fetchall()


def _request(server, data):
    runtime = server.runtime
    node, authority = _identifier(data["nodeId"]), _identifier(data["authorityId"])
    platform = _match(data["platform"], r"[A-Za-z0-9._-]{1,128}")
    _external(runtime, authority)
    if node == authority or runtime.local_authorities or node in runtime.public_keys or _history(runtime, node):
        raise ValueError("joining identity is already assigned")
    intent = _intent(runtime)
    if intent and (intent[:3] != (node, authority, platform) or intent[3] is not None):
        raise ValueError("conflicting enrollment")
    key = load_keypair(server.key_dir, node)
    if not intent:
        if key or any(server.key_dir.glob("*.private")) or any(server.key_dir.glob("*.public")):
            raise ValueError("unclaimed key material")
        # Persist the exclusive identity claim before the recoverable keypair
        # transaction. A retry may use only material belonging to this claim.
        with runtime.db:
            runtime.db.execute("INSERT INTO manager_enrollment VALUES (1, ?, ?, ?, NULL)", (node, authority, platform))
    now = int(time.time())
    pending = _pending(runtime)
    if pending:
        if key is None or key.public_key != pending["publicKey"]:
            raise ValueError("key differs from pending enrollment")
        if now < pending["expiresAt"]:
            return pending
    if key is None:
        key = generate_keypair(server.key_dir, node)
    request = make_enrollment_request(key, node, platform=platform, requested_parent=authority, issued_at=now,
                                      expires_at=now + TTL)
    with runtime.db:
        runtime.db.execute("INSERT INTO manager_enrollment_requests VALUES (?, ?)", (_digest(request), json.dumps(request)))
    return request


def _admit(runtime, record, *, retain, allow_new=True):
    node = record["recordId"]
    if node in runtime.public_keys or runtime._validate(record)[0] != "accepted":
        raise ValueError("identity or issuer is invalid")
    history = _history(runtime, node)
    with runtime.db:
        if history:
            if len(history) != 1 or history[0][0] != "accepted" or json.loads(history[0][1]) != record:
                raise ValueError("identity history conflicts")
        elif not allow_new:
            raise ValueError("approval window closed")
        elif runtime.ingest([record], retain=False, commit=False)[0]["status"] != "accepted":
            raise ValueError("identity admission failed")
        row = runtime.db.execute(
            "SELECT schema, generation, payload FROM projection WHERE record_id = ?", (node,)
        ).fetchone()
        if not row or row[:2] != ("node-identity", 1) or json.loads(row[2]) != record["payload"]:
            raise ValueError("identity is not current")
        if retain and not history:
            # Publish only reconciled and projected evidence. Provider append is
            # idempotent for the exact envelope if its acknowledgement is lost.
            runtime.provider.append(record)


def handle(server, operation, data):
    runtime = server.runtime
    result = {"format": "arbor-manager/runtime-response", "version": 1, "operation": operation, "status": "accepted"}
    if operation == "enrollment/status":
        authority = _identifier(data["authorityId"])
        trusted = _trusted(runtime, authority)
        key = load_keypair(server.key_dir, authority) if trusted else None
        signer = key is not None and key.public_key == runtime.public_keys[authority]
        pending = _pending(runtime)
        intent = _intent(runtime)
        node = intent[0] if intent else None
        if runtime.local_authorities:
            state = "self-rooted"
        elif intent:
            state = "enrolled" if local_identity(server, node) else "pending"
        elif any(server.key_dir.glob("*.private")) or any(server.key_dir.glob("*.public")):
            state = "occupied"
        else:
            state = "new"
        return {**result, "authorityId": authority, "authorityTrusted": trusted, "canApprove": signer,
                "joiningNodeId": node, "enrollmentState": state, "expiresAt": pending["expiresAt"] if pending and state == "pending" else None}
    if operation == "enrollment/request":
        request = _request(server, data)
        return {**result, "nodeId": request["nodeId"], "request": request, "requestDigest": _digest(request)}
    if operation == "enrollment/approve":
        request = data["request"]
        _validate_request(request)
        authority = _identifier(data["authorityId"])
        _external(runtime, authority)
        digest = _digest(request)
        if digest != data["requestDigest"] or request["requestedParent"] != authority:
            raise ValueError("unconfirmed request")
        key = load_keypair(server.key_dir, authority)
        if key is None or runtime.public_keys[authority] != key.public_key:
            raise ValueError("authority signer unavailable")
        record = approve_enrollment(request, key)
        _admit(runtime, record, retain=True, allow_new=request["issuedAt"] <= time.time() < request["expiresAt"])
        return {**result, "nodeId": request["nodeId"], "requestDigest": digest, "approval": record}
    record = data["approval"]
    _validate_approval(record)
    node = _identifier(data["nodeId"])
    digest = record["payload"]["enrollmentRequestDigest"]
    intent = _intent(runtime)
    if not intent or intent[0] != node or intent[3] not in (None, digest) or runtime.local_authorities:
        raise ValueError("no matching local enrollment")
    _verify_local(server, node, record)
    _admit(runtime, record, retain=False)
    with runtime.db:
        runtime.db.execute("UPDATE manager_enrollment SET completed = ? WHERE slot = 1", (digest,))
    return {**result, "nodeId": node, "requestDigest": digest}


def _verify_local(server, node, record):
    p = record["payload"]
    pending = _pending(server.runtime, p["enrollmentRequestDigest"])
    key = load_keypair(server.key_dir, node)
    if (not pending or pending["nodeId"] != node or key is None or key.public_key != pending["publicKey"]
            or p["identity"] != node or p["publicKey"] != key.public_key or p["platform"] != pending["platform"]
            or p["approvedBy"] != pending["requestedParent"]):
        raise ValueError("approval disagrees with local request")
    _external(server.runtime, record["issuer"])
    return key.public_key


def local_identity(server, node=None):
    """Resolve a locally completed enrollment while its approved identity remains current."""
    runtime = server.runtime
    intent = _intent(runtime)
    if not intent or intent[3] is None or node not in (None, intent[0]):
        return None
    node = intent[0]
    history = _history(runtime, node)
    if len(history) != 1 or history[0][0] != "accepted":
        raise ValueError("enrollment conflicts with registry history")
    record = json.loads(history[0][1])
    _validate_approval(record)
    if record["payload"]["enrollmentRequestDigest"] != intent[3]:
        raise ValueError("completed enrollment differs from projection")
    public = _verify_local(server, node, record)
    _admit(runtime, record, retain=False, allow_new=False)
    return node, public
