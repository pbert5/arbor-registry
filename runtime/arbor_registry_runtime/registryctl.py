"""Small, deterministic local control surface for an Arbor Registry runtime."""

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
    OrbitDBProvider,
    Runtime,
    RuntimeKey,
    make_public_record,
    make_identity_generation,
    generate_keypair,
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _write_json_atomic(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _private_key(path: Path, issuer: str, generation: int | None = None) -> RuntimeKey:
    suffix = f".g{generation}" if generation is not None else ""
    private = path / f"{issuer}{suffix}.private"
    # Bootstrap authorities retain their legacy unsuffixed key.  Dynamically
    # enrolled identities use generation-bound files.  This fallback keeps
    # both command families interoperable without copying bootstrap secrets
    # into generation slots.
    if generation is not None and not private.exists():
        private = path / f"{issuer}.private"
    encoded = private.read_text(encoding="ascii").strip()
    signing = SigningKey(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    return RuntimeKey(issuer, signing)


def _config(path: Path) -> dict[str, Any]:
    value = _read_json(path, {})
    if not isinstance(value, dict):
        raise ValueError("runtime config must be a JSON object")
    required = ("stateDir", "transportSocket", "transportTokenFile", "bootstrapAuthoritiesFile", "identityDir")
    if any(not isinstance(value.get(key), str) or not value[key] for key in required):
        raise ValueError("runtime config is missing a required path")
    return value


def _runtime(config: dict[str, Any]) -> tuple[Runtime, OrbitDBProvider]:
    state = Path(config["stateDir"])
    authorities = _read_json(Path(config["bootstrapAuthoritiesFile"]), {})
    if isinstance(authorities, dict) and isinstance(authorities.get("keys"), dict):
        authorities = authorities["keys"]
    if not isinstance(authorities, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in authorities.items()):
        raise ValueError("bootstrap authorities must be a mapping of issuer to public key")
    identities = Path(config["identityDir"])
    keys = dict(authorities)
    for public in identities.glob("*.public"):
        keys[public.name.removesuffix(".public")] = public.read_text(encoding="ascii").strip()
    token = Path(config["transportTokenFile"]).read_text(encoding="utf-8").strip()
    provider = OrbitDBProvider(
        Path(config["transportSocket"]), config.get("stream", "registry"), token=token,
        timeout=float(config.get("transportTimeout", 30)),
    )
    runtime = Runtime(
        state, provider, keys,
        authority_issuers=set(config.get("authorityIssuers", authorities.keys())),
    )
    return runtime, provider


def _format(value: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    elif isinstance(value, dict):
        for key, item in value.items():
            print(f"{key}: {item}")
    else:
        print(value)


def _sync(config: dict[str, Any], runtime: Runtime, provider: OrbitDBProvider, limit: int, pages: int) -> dict[str, Any]:
    cursor_path = Path(config.get("providerCursorFile", Path(config["stateDir"]) / "provider-cursor.json"))
    saved = _read_json(cursor_path, {})
    cursor = saved.get("cursor", "v2:begin") if isinstance(saved, dict) else "v2:begin"
    fetched = accepted = quarantined = 0
    for _ in range(pages):
        records = provider.fetch(cursor, limit)
        next_cursor = provider.next_cursor
        if not records:
            break
        outcomes = runtime.ingest(record for _, record in records)
        fetched += len(records)
        accepted += sum(item.get("status") == "accepted" for item in outcomes)
        quarantined += sum(item.get("status") == "quarantined" for item in outcomes)
        if not isinstance(next_cursor, str) or next_cursor == cursor:
            break
        cursor = next_cursor
        # Persist only after the entire page has been ingested and reconciled.
        _write_json_atomic(cursor_path, {"cursor": cursor})
        if len(records) < limit:
            break
    return {"fetched": fetched, "accepted": accepted, "quarantined": quarantined, "cursor": cursor}


def _record(key: RuntimeKey, schema: str, record_id: str, payload: dict[str, Any], generation: int = 1) -> dict[str, Any]:
    if not schema or not record_id or not isinstance(payload, dict):
        raise ValueError("schema, record id, and object payload are required")
    return make_public_record(key, schema, record_id, payload, generation=generation, issuer_generation=generation)


def _public_command(args: argparse.Namespace, config: dict[str, Any], schema: str, required: tuple[str, ...]) -> dict[str, Any]:
    payload = {field: getattr(args, field) for field in required}
    key = _private_key(Path(config["identityDir"]), args.issuer, args.generation)
    runtime, _ = _runtime(config)
    try:
        result = runtime.ingest([_record(key, schema, args.record_id, payload, args.generation)])
        return result[0]
    finally:
        runtime.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arbor-registryctl")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--format", choices=("human", "json"), default="human")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sync").add_argument("--limit", type=int, default=100)
    sub.choices["sync"].add_argument("--pages", type=int, default=100)
    for name in ("status", "accepted", "projection", "quarantine"):
        sub.add_parser(name)
    record = sub.add_parser("submit")
    record.add_argument("schema")
    record.add_argument("record_id")
    record.add_argument("payload", type=Path)
    record.add_argument("--issuer", required=True)
    record.add_argument("--generation", type=int, default=1)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("issuer")
    keygen.add_argument("--generation", type=int)
    keygen.add_argument("--rotation", action="store_true")
    identity = sub.add_parser("identity-generation")
    identity.add_argument("identity")
    identity.add_argument("public_key")
    identity.add_argument("--issuer", required=True)
    identity.add_argument("--generation", type=int, default=1)
    relationship = sub.add_parser("relationship-add")
    relationship.add_argument("record_id")
    relationship.add_argument("--from", dest="from_node", required=True)
    relationship.add_argument("--to", dest="to_node", required=True)
    relationship.add_argument("--kind", choices=("parent", "peer"), required=True)
    relationship.add_argument("--state", choices=("active", "standby", "suspended", "severed"), default="active")
    relationship.add_argument("--authority-root", required=True)
    relationship.add_argument("--issuer", required=True)
    relationship.add_argument("--generation", type=int, default=1)
    for name, schema, fields in (
        ("endpoint-publish", "endpoint", ("node", "network", "address", "port", "purpose")),
        ("service-publish", "service", ("name", "node", "protocol", "endpoint")),
        ("machine-publish", "machine-facts", ("node", "system", "hostname")),
    ):
        command = sub.add_parser(name)
        command.add_argument("record_id")
        command.add_argument("--issuer", required=True)
        command.add_argument("--generation", type=int, default=1)
        for field in fields:
            command.add_argument(f"--{field}", required=True, type=int if field == "port" else str)
    args = parser.parse_args(argv)
    config = _config(args.config)
    as_json = args.format == "json"
    if args.command == "keygen":
        key = generate_keypair(Path(config["identityDir"]), args.issuer, generation=args.generation, rotation=args.rotation)
        result = {"issuer": key.issuer, "generation": args.generation, "publicKey": key.public_key}
    elif args.command == "submit":
        payload = _read_json(args.payload, None)
        result = _public_command(argparse.Namespace(**vars(args), **payload), config, args.schema, tuple(payload))
    else:
        runtime, provider = _runtime(config)
        try:
            if args.command == "sync":
                result = _sync(config, runtime, provider, args.limit, args.pages)
            elif args.command == "status":
                result = {"runtime": runtime.status(), "transport": provider.status()}
            elif args.command == "accepted":
                result = runtime.accepted()
            elif args.command == "projection":
                result = runtime.projection()
            elif args.command == "quarantine":
                result = runtime.quarantine()
            elif args.command == "relationship-add":
                payload = {"from": args.from_node, "to": args.to_node, "kind": args.kind,
                           "status": args.state, "authorityRoot": args.authority_root}
                key = _private_key(Path(config["identityDir"]), args.issuer, args.generation)
                result = runtime.ingest([_record(key, "relationship", args.record_id, payload, args.generation)])[0]
            elif args.command == "identity-generation":
                key = _private_key(Path(config["identityDir"]), args.issuer)
                record = make_identity_generation(key, args.identity, args.generation, args.public_key)
                result = runtime.ingest([record])[0]
            else:
                schemas = {"endpoint-publish": ("endpoint", ("node", "network", "address", "port", "purpose")),
                           "service-publish": ("service", ("name", "node", "protocol", "endpoint")),
                           "machine-publish": ("machine-facts", ("node", "system", "hostname"))}
                schema, fields = schemas[args.command]
                result = _public_command(args, config, schema, fields)
        finally:
            runtime.close()
    _format(result, as_json)
    return 0
