"""Packaged, deliberately small operator surface for the local registry runtime."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from .runtime import (
    OrbitDBProvider, Runtime, RuntimeKey, canonical_json, generate_keypair,
    make_identity_generation, make_public_record, make_recovery_approval,
    make_recovery_authorization,
)


def _read(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _key(directory: Path, issuer: str, generation: int | None = None) -> RuntimeKey:
    suffix = f".g{generation}" if generation is not None else ""
    path = directory / f"{issuer}{suffix}.private"
    if not path.exists() and generation == 1:
        path = directory / f"{issuer}.private"
    encoded = path.read_text(encoding="ascii").strip()
    return RuntimeKey(issuer, SigningKey(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))))


def _config(path: Path) -> dict[str, Any]:
    value = _read(path, {})
    required = ("stateDir", "transportSocket", "transportTokenFile", "bootstrapAuthoritiesFile", "identityDir")
    if not isinstance(value, dict) or any(not isinstance(value.get(k), str) or not value[k] for k in required):
        raise ValueError("runtime config is missing a required path")
    return value


def _runtime(config: dict[str, Any]) -> tuple[Runtime, OrbitDBProvider]:
    authorities = _read(Path(config["bootstrapAuthoritiesFile"]), {})
    if isinstance(authorities, dict) and isinstance(authorities.get("keys"), dict):
        authorities = authorities["keys"]
    if not isinstance(authorities, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in authorities.items()):
        raise ValueError("bootstrap authorities must be a mapping of issuer to public key")
    keys = dict(authorities)
    identity_dir = Path(config["identityDir"])
    for path in identity_dir.glob("*.public"):
        keys[path.name.removesuffix(".public")] = path.read_text(encoding="ascii").strip()
    token = Path(config["transportTokenFile"]).read_text(encoding="utf-8").strip()
    provider = OrbitDBProvider(Path(config["transportSocket"]), config.get("stream", "registry"), token=token)
    roles = {role: set(values) for role, values in config.get("approverRoles", {}).items()}
    return Runtime(Path(config["stateDir"]), provider, keys,
                   authority_issuers=set(config.get("authorityIssuers", authorities)),
                   approver_roles=roles or None,
                   recovery_thresholds=config.get("recoveryThresholds")), provider


def _public(args: argparse.Namespace, config: dict[str, Any], schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    if schema in {"configuration-intent", "compatibility", "machine-facts", "hardware-snapshot"}:
        node = payload.get("node")
        if node != args.issuer:
            raise ValueError(f"{schema} publication is node-bound to its issuer")
    key = _key(Path(config["identityDir"]), args.issuer, getattr(args, "issuer_generation", None))
    runtime, _ = _runtime(config)
    try:
        return runtime.ingest([make_public_record(key, schema, args.record_id, payload,
                                                   generation=args.record_generation,
                                                   issuer_generation=getattr(args, "issuer_generation", None))])[0]
    finally:
        runtime.close()


def _data_only(value: Any) -> Any:
    blocked = {"secret", "password", "token", "credential", "private", "privatekey", "signingkey",
               "code", "script", "command", "executable"}
    if isinstance(value, dict):
        return {k: _data_only(v) for k, v in sorted(value.items())
                if k.replace("-", "").replace("_", "").lower() not in blocked}
    if isinstance(value, list):
        return [_data_only(v) for v in value]
    return value


def manager_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    """Export the Manager's public node-data contract with stable ordering."""
    source = value.get("nodes", value.get("snapshot", {}).get("nodes", value))
    if not isinstance(source, dict):
        raise ValueError("manager snapshot must contain a nodes object")
    snapshot = {"nodes": {name: _data_only(source[name]) for name in sorted(source)}}
    digest = hashlib.sha256(canonical_json(snapshot)).hexdigest()
    return {"format": "arbor-manager/registry-snapshot", "version": 1, "snapshot": snapshot, "snapshotDigest": digest}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arbor-registryctl")
    parser.add_argument("--config", type=Path, required=False)
    parser.add_argument("--format", choices=("human", "json"), default="human")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen").add_argument("issuer")
    sub.choices["keygen"].add_argument("--generation", type=int)
    sub.choices["keygen"].add_argument("--rotation", action="store_true")
    for name in ("status", "accepted", "projection", "quarantine"):
        sub.add_parser(name)
    for name, schema in (("configuration-intent-publish", "configuration-intent"), ("compatibility-publish", "compatibility")):
        command = sub.add_parser(name); command.set_defaults(schema=schema)
        command.add_argument("record_id"); command.add_argument("payload", type=Path)
        command.add_argument("--issuer", required=True); command.add_argument("--record-generation", type=int, default=1)
        command.add_argument("--issuer-generation", type=int)
    approve = sub.add_parser("recovery-approve")
    approve.add_argument("identity"); approve.add_argument("lost_generation", type=int); approve.add_argument("--role", required=True)
    approve.add_argument("--approver", required=True); approve.add_argument("--approver-generation", type=int, required=True)
    authorize = sub.add_parser("recovery-authorize")
    authorize.add_argument("identity"); authorize.add_argument("lost_generation", type=int); authorize.add_argument("new_public_key")
    authorize.add_argument("approvals", type=Path); authorize.add_argument("--issuer", required=True)
    recover = sub.add_parser("identity-recover")
    recover.add_argument("identity"); recover.add_argument("lost_generation", type=int); recover.add_argument("new_public_key")
    recover.add_argument("approvals", type=Path); recover.add_argument("--issuer", required=True)
    snap = sub.add_parser("manager-snapshot-export"); snap.add_argument("input", type=Path); snap.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "manager-snapshot-export":
        result = manager_snapshot(_read(args.input))
        if args.output: _write(args.output, result)
    elif args.command == "keygen":
        if args.config is None: raise ValueError("--config is required")
        config = _config(args.config); key = generate_keypair(Path(config["identityDir"]), args.issuer, generation=args.generation, rotation=args.rotation)
        result = {"issuer": key.issuer, "generation": args.generation, "publicKey": key.public_key}
    else:
        if args.config is None: raise ValueError("--config is required")
        config = _config(args.config); runtime, provider = _runtime(config)
        try:
            if args.command == "status": result = runtime.status() if hasattr(runtime, "status") else {"accepted": len(runtime.accepted())}
            elif args.command == "accepted": result = runtime.accepted()
            elif args.command == "projection": result = runtime.projection()
            elif args.command == "quarantine": result = runtime.quarantine()
            elif args.command in {"configuration-intent-publish", "compatibility-publish"}:
                result = _public(args, config, args.schema, _read(args.payload))
            elif args.command == "recovery-approve":
                result = make_recovery_approval(_key(Path(config["identityDir"]), args.approver), args.identity, args.lost_generation, role=args.role, approver_generation=args.approver_generation)
            else:
                authority = _key(Path(config["identityDir"]), args.issuer)
                approvals = _read(args.approvals)
                if not isinstance(approvals, list): raise ValueError("approvals must be a JSON list")
                authorization = make_recovery_authorization(authority, args.identity, args.lost_generation, args.new_public_key, approvals)
                if args.command == "identity-recover":
                    result = runtime.ingest([authorization, make_identity_generation(authority, args.identity, args.lost_generation + 1, args.new_public_key, predecessor=f"{args.identity}:{args.lost_generation}", recovery_authorization=authorization)])[1]
                else: result = runtime.ingest([authorization])[0]
        finally: runtime.close()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if args.format == "json" else result)
    return 0
