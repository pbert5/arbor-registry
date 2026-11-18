"""Interactive, role-bound Registry pairing over a Magic Wormhole channel."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import sys
import termios
import time

from twisted.internet import defer, task
from wormhole import create
from wormhole.cli.public_relay import MAILBOX_RELAY

from .daemon import _config, _token

APP_ID = "arbor-registry/pair/v1"
MAX_BYTES = 65536
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIGEST = re.compile(r"[0-9a-f]{64}")
CODE = re.compile(r"[0-9]{1,16}(?:-[a-zA-Z]{1,32}){4}")


def require(condition):
    if not condition:
        raise ValueError("invalid pairing exchange")


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError
    return seconds


async def tty_line(reactor, fd, prompt, deadline, *, hidden=False):
    saved = termios.tcgetattr(fd)
    if hidden:
        private = saved.copy()
        private[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(fd, termios.TCSAFLUSH, private)
    try:
        os.write(fd, prompt.encode())
        while not select.select([fd], [], [], 0)[0]:
            await task.deferLater(reactor, min(0.1, remaining(deadline)), lambda: None)
        line = os.read(fd, 256)
        require(line.endswith(b"\n"))
        return line[:-1].decode("ascii")
    finally:
        if hidden:
            termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
            os.write(fd, b"\n")


def encode(value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False).encode()
    require(len(raw) < MAX_BYTES)
    return raw


def registry(config, deadline, operation, **fields):
    token = _token(Path(config["tokenFile"]))
    raw = encode(dict(operation=f"pair/{operation}", token=token, **fields))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(min(30, remaining(deadline)))
        client.connect(config.get("socket", "/run/arbor-registry/registry.sock"))
        client.sendall(raw + b"\n")
        with client.makefile("rb") as stream:
            reply = stream.readline(MAX_BYTES + 1)
    require(len(reply) <= MAX_BYTES and reply.endswith(b"\n"))
    result = json.loads(reply)
    require(result["ok"] is True and isinstance(result["result"], dict))
    return result["result"]


def send(channel, kind, value):
    channel.send_message(encode({"type": kind, "value": value}))


async def receive(channel, *kinds):
    raw = await channel.get_message()
    require(type(raw) is bytes and len(raw) < MAX_BYTES)
    envelope = json.loads(raw)
    require(type(envelope) is dict and set(envelope) == {"type", "value"})
    require(envelope["type"] in kinds and type(envelope["value"]) is dict)
    return envelope["type"], envelope["value"]


def descriptor(value, name):
    require(type(value) is dict and set(value) == {"identity", "domain", "publicKey", "genesisDigest"})
    require(value["identity"] == name and DIGEST.fullmatch(value["genesisDigest"]))
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value["domain"]))
    require(re.fullmatch(r"[A-Za-z0-9_-]{43}", value["publicKey"]))
    return value


async def exchange(reactor, channel, args, fd, deadline):
    config = _config(Path(args.config))

    def rpc(operation, **fields):
        return registry(config, deadline, operation, **fields)

    parent_side = args.role == "parent"
    local_name = args.parent if parent_side else args.child
    peer_name = args.child if parent_side else args.parent
    local = descriptor(rpc("identity"), local_name)
    if parent_side:
        channel.allocate_code(code_length=4)
        code = await channel.get_code()
        require(CODE.fullmatch(code))
        os.write(fd, f"Pairing code: {code}\n".encode())
    else:
        code = await tty_line(reactor, fd, "Pairing code: ", deadline, hidden=True)
        require(CODE.fullmatch(code))
        channel.set_code(code)
    await channel.get_verifier()
    session = channel.derive_key("arbor-registry/pair/v1/session", 32).hex()
    names = {"parent": args.parent, "child": args.child}
    send(channel, args.role, {**names, "identity": local})
    _, hello = await receive(channel, "child" if parent_side else "parent")
    peer = descriptor(hello.get("identity"), peer_name)
    require(hello == {**names, "identity": peer})
    parent, child = (local, peer) if parent_side else (peer, local)
    require(parent["domain"] == child["domain"])
    os.write(fd, f"Registry domain: {parent['domain']}\n".encode())
    for role, identity in (("Parent", parent), ("Child", child)):
        fingerprint = hashlib.sha256(identity["publicKey"].encode("ascii")).hexdigest()
        os.write(fd, f"{role} {identity['identity']} public-key fingerprint: {fingerprint}\n".encode())
    answer = await tty_line(reactor, fd, f"Approve parent {args.parent} and child {args.child}? Type yes: ", deadline)
    require(answer == "yes")
    status = rpc("status", **names)
    if parent_side:
        kind, message = await receive(channel, "request", "certificate")
        if kind == "request":
            require(status["paired"] is False)
            check_request(message, parent, child, session)
            approval = rpc("approve", request=message, session=session)
            send(channel, "approval", approval)
            _, certificate = await receive(channel, "certificate")
            require(certificate["approval"] == approval)
        else:
            certificate = message
        check_certificate(certificate, parent, child)
        if status["paired"]:
            require(status["certificate"] == certificate)
        rpc("commit", certificate=certificate)
        status = rpc("status", **names)
        require(status["paired"] is True and status["certificate"] == certificate)
        digest = status["digest"]
        require(DIGEST.fullmatch(digest))
        send(channel, "committed", {"digest": digest})
        _, acknowledgment = await receive(channel, "readback")
        require(acknowledgment == {"digest": digest})
    else:
        if status["paired"] is False:
            request = rpc("request", parent=parent, session=session)
            check_request(request, parent, child, session)
            send(channel, "request", request)
            _, approval = await receive(channel, "approval")
            require(approval["request"] == request)
            rpc("accept", approval=approval, session=session)
            status = rpc("status", **names)
            require(status["certificate"]["approval"] == approval)
        require(status["paired"] is True)
        certificate = status["certificate"]
        check_certificate(certificate, parent, child)
        digest = status["digest"]
        require(DIGEST.fullmatch(digest))
        send(channel, "certificate", certificate)
        _, committed = await receive(channel, "committed")
        require(committed == {"digest": digest})
        send(channel, "readback", {"digest": digest})
    return digest


def check_request(request, parent, child, session):
    require(request["parent"] == parent and request["child"] == child and request["session"] == session)


def check_certificate(certificate, parent, child):
    request = certificate["approval"]["request"]
    require(request["parent"] == parent and request["child"] == child)


async def run(reactor, args):
    deadline = time.monotonic() + args.timeout
    if args.role == "status":
        config = _config(Path(args.config))
        names = {"parent": args.parent, "child": args.child}
        result = registry(config, deadline, "status", **names)
        paired, digest = result["paired"], result["digest"]
        require(type(paired) is bool and (DIGEST.fullmatch(digest) if paired else digest is None))
        print(json.dumps({**names, "paired": paired, "digest": digest}, sort_keys=True))
        return
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    original_tty = termios.tcgetattr(fd)
    restore = reactor.addSystemEventTrigger("before", "shutdown", termios.tcsetattr,
                                            fd, termios.TCSANOW, original_tty)
    try:
        channel = create(APP_ID, args.relay_url, reactor)
        try:
            digest = await defer.ensureDeferred(exchange(reactor, channel, args, fd, deadline)).addTimeout(
                remaining(deadline), reactor)
        finally:
            await channel.close().addTimeout(3, reactor)
    finally:
        reactor.removeSystemEventTrigger(restore)
        os.close(fd)
    print(f"Paired parent {args.parent} and child {args.child} ({digest}).")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="arbor-registry-pair")
    parser.add_argument("role", choices=("parent", "child", "status"))
    parser.add_argument("--parent", required=True)
    parser.add_argument("--child", required=True)
    parser.add_argument("--config", default=os.environ.get("ARBOR_REGISTRY_CONFIG", "/etc/arbor-registry/config.json"))
    parser.add_argument("--relay-url", default=MAILBOX_RELAY)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    if not (NAME.fullmatch(args.parent) and NAME.fullmatch(args.child)
            and args.parent != args.child and 1 <= args.timeout <= 600):
        parser.error("expected distinct Registry identities and a timeout of 1 to 600 seconds")

    completed = False

    async def start(reactor):
        nonlocal completed
        try:
            await run(reactor, args)
            completed = True
        except Exception:
            print("Registry pairing failed or was cancelled.", file=sys.stderr)
            raise SystemExit(1) from None

    try:
        task.react(start)
    except SystemExit as exit_status:
        # An external signal can stop Twisted before the exchange completes.
        return exit_status.code or int(not completed)


if __name__ == "__main__":
    raise SystemExit(main())
