"""Live-network tests use loopback servers only (allow_private=True stands in for the internet)."""
import os
import socket
import struct
import threading
from types import SimpleNamespace

import yaml
from assemblyline_v4_service.common.result import Result

from elfsim_service.elfsim_service import ElfSim
from elfsim_service.emulator import emulate
from elfsim_service.network import LiveNetwork
from test.unit.elfbuilder import Prog

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "..", "service_manifest.yml")
MANIFEST = yaml.safe_load(open(os.environ["SERVICE_MANIFEST_PATH"]))
GREETING = b"HELLO-FROM-REMOTE"


class Remote:
    """TCP server: sends ``payload`` on connect, then echoes."""

    def __init__(self, payload=GREETING):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port, self.payload = self.srv.getsockname()[1], payload
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


def _tcp_reader_guest(port: int) -> Prog:
    p = Prog()
    addr, buf = p.d(Prog.sockaddr_in("127.0.0.1", port)), p.d(b"\0" * 64)
    p.sys(359, 2, 1, 0)
    p.ebx_from_eax()
    p.mov(1, addr); p.mov(2, 16); p.mov(0, 362)
    p.raw(b"\xcd\x80")                                   # connect
    p.mov(1, buf); p.mov(2, 64); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 371)
    p.raw(b"\xcd\x80")                                   # recvfrom -> length in eax
    p.edx_from_eax()
    p.sys(4, 1, buf)                                     # write(1, buf, edx)
    p.exit(0)
    return p


def test_only_public_addresses_are_reachable_by_default():
    n = LiveNetwork()
    assert n.allows("8.8.8.8", 53) and n.allows("1.1.1.1", 443)
    for internal in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.5", "169.254.169.254",
                     "100.64.0.1", "0.0.0.0", "224.0.0.1", "not-an-ip"):
        assert not n.allows(internal, 80), internal
    assert not n.allows("8.8.8.8", 0) and not n.allows("8.8.8.8", 70000)


def test_with_a_live_network_the_guest_receives_real_bytes():
    remote = Remote()
    r = emulate(_tcp_reader_guest(remote.port).build(), timeout_s=15, network=LiveNetwork(allow_private=True))
    assert r.stdout == GREETING
    assert [x["data"] for x in r.received] == [GREETING]
    assert any(e.get("live") is True for e in r.events if e["syscall"] == "connect")


def test_without_a_network_the_same_guest_stays_simulated():
    remote = Remote()
    r = emulate(_tcp_reader_guest(remote.port).build(), timeout_s=15)
    assert r.stdout == b"" and r.received == []


def test_internal_addresses_stay_simulated_even_when_internet_is_on():
    remote = Remote()        # listens on loopback: an internal address
    r = emulate(_tcp_reader_guest(remote.port).build(), timeout_s=15, network=LiveNetwork())
    assert r.stdout == b"" and r.received == []


def test_a_failed_real_connection_is_reported_not_faked():
    closed = socket.socket(); closed.bind(("127.0.0.1", 0)); port = closed.getsockname()[1]; closed.close()
    r = emulate(_tcp_reader_guest(port).build(), timeout_s=15, network=LiveNetwork(allow_private=True))
    connect = next(e for e in r.events if e["syscall"] == "connect")
    assert connect["live"] is False and r.received == []


def test_udp_datagrams_are_sent_and_answered_for_real():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.sendto(b"PONG:" + (d := srv.recvfrom(100))[0], d[1]), daemon=True).start()
    p = Prog()
    dest, q, buf = p.d(Prog.sockaddr_in("127.0.0.1", port)), p.d(b"ping"), p.d(b"\0" * 64)
    p.sys(359, 2, 2, 0)
    p.ebx_from_eax()
    p.mov(1, q); p.mov(2, 4); p.mov(6, 0); p.mov(7, dest); p.mov(5, 16); p.mov(0, 369)
    p.raw(b"\xcd\x80")                                   # sendto
    p.mov(1, buf); p.mov(2, 64); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 371)
    p.raw(b"\xcd\x80")                                   # recvfrom
    p.edx_from_eax()
    p.sys(4, 1, buf)
    p.exit(0)
    r = emulate(p.build(), timeout_s=15, network=LiveNetwork(allow_private=True))
    assert r.stdout == b"PONG:ping"


# ---- what the service does with what came back -------------------------------------------
class _Req:
    def __init__(self):
        self.extracted = []

    def add_extracted(self, path, name, desc, **kw):
        self.extracted.append((name, open(path, "rb").read()))
        return True


def _received_section(received, tmp_path, monkeypatch):
    monkeypatch.setattr(ElfSim, "working_directory", property(lambda self: str(tmp_path)))
    req, result = _Req(), Result()
    ElfSim()._received(req, result, SimpleNamespace(received=received))
    return result.sections, req


def test_small_replies_are_shown_as_text_but_not_extracted(tmp_path, monkeypatch):
    replies = [{"ip": "203.0.113.9", "port": 4444, "data": b"\x00"}] * 40
    (section,), req = _received_section(replies, tmp_path, monkeypatch)
    assert "<- 203.0.113.9:4444" in section.body and "·    x40" in section.body
    assert req.extracted == [] and section.heuristic.score == 0


def test_a_large_stream_is_extracted_as_a_payload_and_scores(tmp_path, monkeypatch):
    blob = b"\x7fELF" + bytes(range(200))
    replies = [{"ip": "203.0.113.9", "port": 80, "data": blob[:100]}, {"ip": "203.0.113.9", "port": 80, "data": blob[100:]}]
    (section,), req = _received_section(replies, tmp_path, monkeypatch)
    assert req.extracted == [("received_203.0.113.9_80.bin", blob)]
    assert section.heuristic.score == 300


def test_manifest_exposes_the_internet_flag_off_by_default_and_the_pod_can_connect():
    param = next(p for p in MANIFEST["submission_params"] if p["name"] == "allow_internet")
    assert param["type"] == "bool" and param["default"] is False and param["value"] is False
    assert MANIFEST["docker_config"]["allow_internet_access"] is True
    assert MANIFEST["is_external"] is True
    assert "wait_for_update" not in MANIFEST
