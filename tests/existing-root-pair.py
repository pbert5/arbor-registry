"""Run with the installed runtime, transport, pexpect and mailbox server on PATH."""
import contextlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
import threading

import pexpect

PARENT = "r640-0"
CHILD = "eVolver"
NAMES = ["--parent", PARENT, "--child", CHILD]
REVERSED = ["--parent", CHILD, "--child", PARENT]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def service(stack, args, directory, **variables):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARBOR_")}
    process = subprocess.Popen(args, cwd=directory, env={**env, **variables},
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stack.callback(stop, process)
    return process


def wait_service(process, probe):
    until = time.monotonic() + 25
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError("fixture service exited during startup")
        try:
            if probe():
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("fixture service startup timed out")


class Root:
    def __init__(self, stack, directory, name):
        self.stack, self.directory, self.name = stack, directory / name, name
        self.directory.mkdir(mode=0o700)
        self.token = secrets.token_hex(32)
        token_file = self.directory / "token"
        token_file.write_text(self.token)
        token_file.chmod(0o600)
        self.config = self.directory / "config.json"
        self.socket = self.directory / "registry.sock"
        transport_socket = self.directory / "transport.sock"
        self.config.write_text(json.dumps({
            "socket": str(self.socket), "tokenFile": str(token_file),
            "stateDir": str(self.directory / "registry"),
            "transportSocket": str(transport_socket),
            "bootstrapAuthoritiesFile": str(self.directory / "no-bootstrap.json"),
        }))
        transport = service(stack, ["arbor-registry-transport"], self.directory,
                            ARBOR_REGISTRY_SOCKET_TOKEN_FILE=str(token_file),
                            ARBOR_REGISTRY_SOCKET=str(transport_socket),
                            ARBOR_REGISTRY_STATE_DIR=str(self.directory / "orbitdb"))
        wait_service(transport, transport_socket.is_socket)
        self.start()
        initialized = self.manager("identity/init-self", domain="arbor.internal")
        assert initialized["selfRooted"] and initialized["localGenesis"]
        self.fingerprint = initialized["publicFingerprint"]

    def start(self):
        self.daemon = service(self.stack, ["arbor-registryd", "--config", str(self.config)],
                              self.directory)
        wait_service(self.daemon, lambda: self.call("health")["ok"])

    def call(self, operation, **fields):
        request = {"token": self.token, "operation": operation, **fields}
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(8)
            client.connect(str(self.socket))
            client.sendall(json.dumps(request).encode() + b"\n")
            with client.makefile("rb") as stream:
                return json.loads(stream.readline())

    def manager(self, operation, **extra):
        answer = self.call(operation, protocol="arbor-manager/runtime-adapter", version=1,
                           data={"nodeId": self.name, **extra})
        assert answer["status"] == "accepted"
        return answer

    def status(self, names=NAMES):
        return json.loads(subprocess.check_output(
            ["arbor-registry-pair", "status", "--config", str(self.config), *names],
            timeout=10))


@contextlib.contextmanager
def drop_parent_commit(parent):
    """Forward real daemon RPCs until the child sends its signed certificate."""
    dropped = threading.Event()

    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            request = self.rfile.readline(65537)
            if json.loads(request)["operation"] == "pair/commit":
                dropped.set()
                return
            with socket.socket(socket.AF_UNIX) as backend:
                backend.settimeout(8)
                backend.connect(str(parent.socket))
                backend.sendall(request)
                with backend.makefile("rb") as stream:
                    self.wfile.write(stream.readline(65537))

    path = parent.directory / "interrupt.sock"
    config = parent.directory / "interrupt.json"
    config.write_text(json.dumps({**json.loads(parent.config.read_text()), "socket": str(path)}))
    with socketserver.UnixStreamServer(str(path), Proxy) as proxy:
        thread = threading.Thread(target=proxy.serve_forever)
        thread.start()
        try:
            yield config
            assert dropped.is_set(), "interruption did not reach parent commit"
        finally:
            proxy.shutdown()
            thread.join()



@contextlib.contextmanager
def corrupt_child_signature(child):
    """Tamper with a signed request after the real child daemon creates it."""
    changed = threading.Event()

    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            request = self.rfile.readline(65537)
            with socket.socket(socket.AF_UNIX) as backend:
                backend.settimeout(8)
                backend.connect(str(child.socket))
                backend.sendall(request)
                with backend.makefile("rb") as stream:
                    reply = json.loads(stream.readline(65537))
            if json.loads(request)["operation"] == "pair/request":
                signature = reply["result"]["signature"]
                reply["result"]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
                changed.set()
            self.wfile.write(json.dumps(reply).encode() + b"\n")

    path = child.directory / "tamper.sock"
    config = child.directory / "tamper.json"
    config.write_text(json.dumps({**json.loads(child.config.read_text()), "socket": str(path)}))
    with socketserver.UnixStreamServer(str(path), Proxy) as proxy:
        thread = threading.Thread(target=proxy.serve_forever)
        thread.start()
        try:
            yield config
            assert changed.is_set(), "signed request was not tampered with"
        finally:
            proxy.shutdown()
            thread.join()



@contextlib.contextmanager
def alter_signed_identity(parent, malformed):
    """Alter the peer identity in the real signed request at the approval RPC."""
    changed = threading.Event()

    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            request = json.loads(self.rfile.readline(65537))
            if request["operation"] == "pair/approve":
                peer = request["request"]["child"]
                public = peer["publicKey"]
                peer["publicKey"] = "!" if malformed else ("A" if public[0] != "A" else "B") + public[1:]
                changed.set()
            with socket.socket(socket.AF_UNIX) as backend:
                backend.settimeout(8)
                backend.connect(str(parent.socket))
                backend.sendall(json.dumps(request).encode() + b"\n")
                with backend.makefile("rb") as stream:
                    self.wfile.write(stream.readline(65537))

    path = parent.directory / "identity-tamper.sock"
    config = parent.directory / "identity-tamper.json"
    config.write_text(json.dumps({**json.loads(parent.config.read_text()), "socket": str(path)}))
    with socketserver.UnixStreamServer(str(path), Proxy) as proxy:
        thread = threading.Thread(target=proxy.serve_forever)
        thread.start()
        try:
            yield config
            assert changed.is_set(), "signed peer identity was not altered"
        finally:
            proxy.shutdown()
            thread.join()
    path.unlink()


def authority_snapshot(root):
    return (root.call("projection")["records"], root.manager("identity/inspect"),
            root.status())


def expect(terminal, pattern):
    # pexpect's ordinary exception includes terminal buffers and the secret.
    if terminal.expect([pattern, pexpect.EOF, pexpect.TIMEOUT]) != 0:
        raise AssertionError("CLI closed or timed out before expected prompt")
    return terminal.match


def finished(terminal, success):
    if terminal.expect([pexpect.EOF, pexpect.TIMEOUT]) != 0:
        raise AssertionError("CLI did not terminate")
    terminal.close()
    assert (terminal.exitstatus == 0) == success


def session(parent, child, relay, scenario, parent_config=None, old_code=None, child_config=None, baseline=None):
    with contextlib.ExitStack() as stack:
        def cli(root, role, names):
            config = (parent_config if role == "parent" and parent_config else
                      child_config if role == "child" and child_config else root.config)
            args = [role, "--config", str(config), *names, "--relay-url", relay,
                    "--timeout", "12"]
            proc = pexpect.spawn("arbor-registry-pair", args, encoding="utf-8", timeout=18)
            stack.callback(proc.close, force=True)
            return proc

        sender = cli(parent, "parent", NAMES)
        code = expect(sender, r"Pairing code: ([0-9]+(?:-[a-zA-Z]+){4})\s").group(1)
        if scenario == "interrupt":
            sender.close(force=True)
            return code
        if scenario == "expire":
            finished(sender, False)
            return code
        names = REVERSED if scenario == "reversed" else NAMES
        receiver = cli(child, "child", names)
        index = receiver.expect(["Pairing code: ", pexpect.EOF, pexpect.TIMEOUT])
        if index == 0:
            if scenario == "closed-code":
                code = old_code
            if scenario == "wrong-code":
                words = code.split("-")
                words[-1] = "aardvark" if words[-1] != "aardvark" else "absurd"
                code = "-".join(words)
            receiver.sendline(code)
        else:
            assert index == 1 and scenario == "reversed"
        if scenario in {"wrong-code", "reversed", "closed-code"}:
            finished(receiver, False)
            finished(sender, False)
            return
        prompt = rf"Approve parent {PARENT} and child {CHILD}\? Type yes: "
        pending = [receiver, sender]
        deadline = time.monotonic() + 15
        while pending and time.monotonic() < deadline:
            for proc in pending.copy():
                index = proc.expect([prompt, pexpect.EOF, pexpect.TIMEOUT], timeout=0.1)
                if index == 0:
                    lines = proc.before.splitlines()
                    parent_line = f"Parent {PARENT} public-key fingerprint: {parent.fingerprint}"
                    child_line = f"Child {CHILD} public-key fingerprint: {child.fingerprint}"
                    assert parent_line in lines and child_line in lines
                    assert lines.index(parent_line) < lines.index(child_line)
                    # Neither daemon may grant the relationship before both approvals.
                    if baseline is not None:
                        assert [authority_snapshot(root) for root in (parent, child)] == baseline
                    proc.sendline("no" if scenario == "decline" and proc is sender else "yes")
                    pending.remove(proc)
                elif index == 1:
                    assert scenario == "decline" and proc is receiver
                    pending.remove(proc)
        assert not pending, "approval prompt timed out"
        for proc in (sender, receiver):
            finished(proc, scenario == "success")
        return code


def main():
    with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
        directory = Path(temp)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        mailbox = service(stack, [sys.executable, "-m", "twisted", "wormhole-mailbox",
                                  "--port", f"tcp:{port}:interface=127.0.0.1"], directory)

        def listening():
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True

        wait_service(mailbox, listening)
        relay = f"ws://127.0.0.1:{port}/v1"
        parent, child = (Root(stack, directory, name) for name in (PARENT, CHILD))
        assert parent.fingerprint != child.fingerprint
        baseline = [authority_snapshot(root) for root in (parent, child)]
        expired_code = session(parent, child, relay, "expire")
        session(parent, child, relay, "closed-code", old_code=expired_code)
        assert [authority_snapshot(root) for root in (parent, child)] == baseline
        closed_code = session(parent, child, relay, "interrupt")
        session(parent, child, relay, "closed-code", old_code=closed_code)
        assert all(not root.status()["paired"] for root in (parent, child))
        for scenario in ("wrong-code", "reversed", "decline"):
            session(parent, child, relay, scenario, baseline=baseline)
            assert [authority_snapshot(root) for root in (parent, child)] == baseline
            assert all(not root.status()["paired"] for root in (parent, child))
        with corrupt_child_signature(child) as tampered:
            session(parent, child, relay, "tampered", child_config=tampered, baseline=baseline)
        assert all(not root.status()["paired"] for root in (parent, child))
        assert [authority_snapshot(root) for root in (parent, child)] == baseline
        for malformed in (True, False):
            with alter_signed_identity(parent, malformed) as tampered:
                session(parent, child, relay, "tampered", parent_config=tampered, baseline=baseline)
            assert [authority_snapshot(root) for root in (parent, child)] == baseline
        with drop_parent_commit(parent) as interrupted:
            session(parent, child, relay, "dropped", interrupted)
        incomplete = child.status()
        assert incomplete["paired"] and not parent.status()["paired"]
        stop(parent.daemon)
        stop(child.daemon)
        parent.start()
        child.start()
        consumed_code = session(parent, child, relay, "success")
        proof = parent.status()
        assert proof == incomplete
        assert proof["paired"] and proof["digest"] and proof == child.status()
        committed = [authority_snapshot(root) for root in (parent, child)]
        certificates = [root.call("pair/status", parent=PARENT, child=CHILD)["result"]
                        for root in (parent, child)]
        session(parent, child, relay, "closed-code", old_code=consumed_code)
        assert [authority_snapshot(root) for root in (parent, child)] == committed
        assert parent.status() == proof == child.status()
        assert [root.call("pair/status", parent=PARENT, child=CHILD)["result"]
                for root in (parent, child)] == certificates
        session(parent, child, relay, "success")
        for root in (parent, child):
            assert root.status() == proof
            stop(root.daemon)
            root.start()
            assert root.status() == proof
            identity = root.manager("identity/inspect")
            assert identity["localGenesis"] and identity["publicFingerprint"] == root.fingerprint
        for root, other in ((parent, child), (child, parent)):
            edges = [record["payload"] for record in root.call("projection")["records"].values()
                     if record["schema"] == "relationship"]
            assert len(edges) == 1
            assert (edges[0]["from"], edges[0]["to"], edges[0]["kind"], edges[0]["status"]) == (
                PARENT, CHILD, "parent", "active")
            assert not root.status(REVERSED)["paired"]
            foreign = next(record for record in other.call("accepted")["records"]
                           if record["schema"] == "node-identity" and record["issuer"] == other.name)
            assert root.call("ingest", records=[foreign])["outcomes"][0]["status"] == "quarantined"
        print("Existing-root CLI pairing passed on two restarted Registry daemons.")


if __name__ == "__main__":
    main()
