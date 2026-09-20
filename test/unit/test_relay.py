"""Relay tests run against a local loopback "remote end" only; no real network is touched."""
import json
import socket
import threading
import time

import pytest

from elfsim_service.emulator import emulate
from elfsim_service.relay import RelayClient, RelayServer
from test.unit.elfbuilder import Prog

GREETING = b"HELLO-FROM-REMOTE"


class Remote:
    """Tiny TCP server: sends ``payload`` on connect, then echoes whatever it receives."""

    def __init__(self, payload=GREETING):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.payload = payload
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.sendall(self.payload)
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


@pytest.fixture
def remote():
    r = Remote()
    yield r
    r.srv.close()


def _start_relay(tmp_path, allow, **kw):
    kw.setdefault("allow_private", True)   # the loopback test remote is not a global address
    path = str(tmp_path / "r.sock")
    server = RelayServer(set(allow), str(tmp_path / "cap"), **kw)
    threading.Thread(target=server.serve, args=(path,), daemon=True).start()
    for _ in range(50):
        try:
            socket.socket(socket.AF_UNIX).connect(path)
            break
        except OSError:
            time.sleep(0.05)
    return server, path


def _capture(tmp_path):
    try:
        return [json.loads(l) for l in open(tmp_path / "cap")]
    except FileNotFoundError:
        return []


def test_relay_forwards_both_ways_and_logs_everything(tmp_path, remote):
    ep = f"127.0.0.1:{remote.port}"
    server, path = _start_relay(tmp_path, {ep})
    client = RelayClient(path, {ep})
    session = client.open("127.0.0.1", remote.port)
    assert session is not None
    client.wait_any([session], 3)
    assert session.recv(100) == GREETING
    assert session.send(b"ping") == 4
    client.wait_any([session], 3)
    assert session.recv(100) == b"ping"
    client.close_all()
    time.sleep(0.3)
    recs = _capture(tmp_path)
    assert {"in", "out"} <= {r["dir"] for r in recs}
    assert (tmp_path / "cap.s1.in.bin").read_bytes() == GREETING + b"ping"
    server.stop()


def test_endpoint_not_on_the_allow_list_is_refused_by_the_server(tmp_path, remote):
    server, path = _start_relay(tmp_path, {"127.0.0.1:1"})
    assert RelayClient(path, set()).open("127.0.0.1", remote.port) is None
    assert any(r["dir"] == "refused" and "allow-list" in r["note"] for r in _capture(tmp_path))
    server.stop()


def test_non_global_addresses_are_refused_unless_explicitly_allowed(tmp_path, remote):
    ep = f"127.0.0.1:{remote.port}"
    server, path = _start_relay(tmp_path, {ep}, allow_private=False)
    assert RelayClient(path, {ep}).open("127.0.0.1", remote.port) is None
    assert any("non-global" in r.get("note", "") for r in _capture(tmp_path))
    server.stop()


def test_session_cap_stops_a_reconnect_loop_from_hammering_the_remote(tmp_path, remote):
    ep = f"127.0.0.1:{remote.port}"
    server, path = _start_relay(tmp_path, {ep}, max_sessions=2)
    client = RelayClient(path, {ep})
    assert client.open("127.0.0.1", remote.port) is not None
    assert client.open("127.0.0.1", remote.port) is not None
    assert client.open("127.0.0.1", remote.port) is None
    server.stop()


def test_inbound_byte_cap_ends_the_session(tmp_path):
    big = Remote(payload=b"A" * 5000)
    ep = f"127.0.0.1:{big.port}"
    server, path = _start_relay(tmp_path, {ep}, max_inbound=100)
    client = RelayClient(path, {ep})
    client.open("127.0.0.1", big.port)
    time.sleep(0.8)
    assert any("inbound cap" in r.get("note", "") for r in _capture(tmp_path))
    server.stop()
    big.srv.close()


def _guest_that_reads_from(port: int) -> Prog:
    p = Prog()
    addr = p.d(Prog.sockaddr_in("127.0.0.1", port))
    buf = p.d(b"\0" * 64)
    p.sys(359, 2, 1, 0)                      # socket(AF_INET, SOCK_STREAM)
    p.ebx_from_eax()
    p.mov(1, addr); p.mov(2, 16); p.mov(0, 362)
    p.raw(b"\xcd\x80")                        # connect
    p.mov(1, buf); p.mov(2, 64); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 371)
    p.raw(b"\xcd\x80")                        # recvfrom -> eax = bytes received
    p.edx_from_eax()
    p.sys(4, 1, buf)                          # write(1, buf, edx)
    p.exit(0)
    return p


def test_guest_receives_relayed_bytes_and_the_report_keeps_them(tmp_path, remote):
    ep = f"127.0.0.1:{remote.port}"
    server, path = _start_relay(tmp_path, {ep})
    r = emulate(_guest_that_reads_from(remote.port).build(), timeout_s=15,
                relay=RelayClient(path, {ep}))
    assert r.stdout == GREETING
    assert [x["data"] for x in r.received] == [GREETING]
    assert any(e.get("relayed") is True for e in r.events if e["syscall"] == "connect")
    server.stop()


def test_without_a_relay_the_same_guest_stays_fully_simulated(remote):
    r = emulate(_guest_that_reads_from(remote.port).build(), timeout_s=15)
    assert r.stdout == b"" and r.received == []          # simulated EOF, nothing real contacted


def test_endpoint_outside_the_client_allow_list_is_never_relayed(tmp_path, remote):
    server, path = _start_relay(tmp_path, {f"127.0.0.1:{remote.port}"})
    r = emulate(_guest_that_reads_from(remote.port).build(), timeout_s=15,
                relay=RelayClient(path, {"127.0.0.1:1"}))
    assert r.received == [] and _capture(tmp_path) == []   # relay was never even asked
    server.stop()


def test_unreachable_relay_makes_connect_fail_instead_of_pretending(tmp_path, remote):
    r = emulate(_guest_that_reads_from(remote.port).build(), timeout_s=15,
                relay=RelayClient(str(tmp_path / "missing.sock"), {f"127.0.0.1:{remote.port}"}))
    connect = next(e for e in r.events if e["syscall"] == "connect")
    assert connect["relayed"] is False and r.received == []
