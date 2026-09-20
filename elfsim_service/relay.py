"""Opt-in, allow-listed relay between the emulated sample and ONE real C2 endpoint.

The emulator (which never has a network stack of its own) talks to this relay over a unix
socket. The relay runs on the host, forwards bytes only to endpoints on an explicit
allow-list (ip:port, no DNS), caps the number of sessions / bytes / time, and logs every
byte in both directions. Everything else the sample tries to reach stays simulated.

Nothing received from the remote end is ever parsed or executed here: it is copied into the
guest's memory buffers (by the fake kernel) and into the capture log as hex.

Server (on the host):
    python -m elfsim_service.relay serve --socket /path/relay.sock \
        --allow 203.0.113.9:4444 --capture capture.jsonl
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import select
import socket
import threading
import time
from typing import Optional


# ============================================================================ client
class RelaySession:
    """One relayed TCP stream, as seen from the emulator side."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.closed = False

    def send(self, data: bytes) -> int:
        if self.closed:
            return -1
        try:
            self.sock.sendall(data)
            return len(data)
        except OSError:
            self.close()
            return -1

    def readable(self) -> bool:
        """True if data is waiting or the far end closed (a recv would not block)."""
        if self.closed:
            return True
        return bool(select.select([self.sock], [], [], 0)[0])

    def recv(self, n: int) -> Optional[bytes]:
        """Bytes now available, b"" on EOF, or None if nothing is available yet."""
        if self.closed:
            return b""
        if not self.readable():
            return None
        try:
            data = self.sock.recv(n)
        except OSError:
            data = b""
        if not data:
            self.close()
        return data

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.sock.close()
            except OSError:
                pass


class RelayClient:
    def __init__(self, socket_path: str, allow: set) -> None:
        self.socket_path = socket_path
        self.allow = set(allow)
        self.sessions: list = []

    def allows(self, ip: str, port: int) -> bool:
        return f"{ip}:{port}" in self.allow

    def open(self, ip: str, port: int) -> Optional[RelaySession]:
        """Ask the relay for a stream to ip:port; None if refused/unavailable."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(12)
        try:
            s.connect(self.socket_path)
            s.sendall(f"CONNECT {ip} {port}\n".encode())
            reply = b""
            while not reply.endswith(b"\n") and len(reply) < 200:
                chunk = s.recv(1)
                if not chunk:
                    break
                reply += chunk
        except OSError:
            s.close()
            return None
        if reply.strip() != b"OK":
            s.close()
            return None
        s.settimeout(None)
        session = RelaySession(s)
        self.sessions.append(session)
        return session

    @staticmethod
    def wait_any(sessions, timeout: float) -> float:
        """Really wait (bounded) until one of the sessions is readable; return seconds waited."""
        live = [s.sock for s in sessions if not s.closed]
        if not live or timeout <= 0:
            return 0.0
        start = time.monotonic()
        select.select(live, [], [], timeout)
        return time.monotonic() - start

    def close_all(self) -> None:
        for s in self.sessions:
            s.close()


# ============================================================================ server
class RelayServer:
    def __init__(self, allow: set, capture_path: str, *, max_sessions: int = 5,
                 max_session_seconds: float = 60.0, max_inbound: int = 1 << 20,
                 max_outbound: int = 1 << 16, connect_timeout: float = 8.0,
                 allow_private: bool = False) -> None:
        self.allow = set(allow)
        self.capture_path = capture_path
        self.max_sessions = max_sessions
        self.max_session_seconds = max_session_seconds
        self.max_inbound, self.max_outbound = max_inbound, max_outbound
        self.connect_timeout = connect_timeout
        self.allow_private = allow_private
        self._lock = threading.Lock()
        self.started = 0
        self._stop = threading.Event()

    def _capture(self, session: int, direction: str, data: bytes = b"", note: str = "") -> None:
        rec = {"t": round(time.time(), 3), "session": session, "dir": direction, "bytes": len(data)}
        if data:
            rec["hex"] = data[:4096].hex()
        if note:
            rec["note"] = note
        with self._lock, open(self.capture_path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    def _validate(self, ip: str, port: int) -> Optional[str]:
        if f"{ip}:{port}" not in self.allow:
            return "not on the allow-list"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "not an IP literal"
        if not self.allow_private and not addr.is_global:
            return "non-global address refused"
        return None

    def handle(self, client: socket.socket) -> None:
        session = 0
        up: Optional[socket.socket] = None
        try:
            client.settimeout(5)
            line = b""
            while not line.endswith(b"\n") and len(line) < 128:
                chunk = client.recv(1)
                if not chunk:
                    return
                line += chunk
            parts = line.decode("latin-1").split()
            if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].isdigit():
                client.sendall(b"ERR bad request\n")
                return
            ip, port = parts[1], int(parts[2])
            problem = self._validate(ip, port)
            if problem:
                self._capture(0, "refused", note=f"{ip}:{port} {problem}")
                client.sendall(f"ERR {problem}\n".encode())
                return
            with self._lock:
                if self.started >= self.max_sessions:
                    over = True
                else:
                    over = False
                    self.started += 1
                    session = self.started
            if over:
                self._capture(0, "refused", note="session limit reached")
                client.sendall(b"ERR session limit\n")
                return
            try:
                up = socket.create_connection((ip, port), timeout=self.connect_timeout)
            except OSError as e:
                self._capture(session, "connect_failed", note=str(e))
                client.sendall(b"ERR connect failed\n")
                return
            self._capture(session, "connected", note=f"{ip}:{port}")
            client.sendall(b"OK\n")
            self._pump(session, client, up)
        finally:
            for s in (up, client):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _pump(self, session: int, client: socket.socket, up: socket.socket) -> None:
        deadline = time.monotonic() + self.max_session_seconds
        inbound = outbound = 0
        # Byte-exact copy of everything the remote end sent, so a pushed payload can be
        # recovered as a plain (non-executable, 0600) file. It is never parsed or run here.
        raw_path = f"{self.capture_path}.s{session}.in.bin"
        raw_fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        raw = os.fdopen(raw_fd, "wb")
        client.settimeout(None)
        up.settimeout(None)
        why = "deadline"
        try:
            while time.monotonic() < deadline and not self._stop.is_set():
                ready, _, _ = select.select([client, up], [], [], 0.5)
                if client in ready:
                    data = client.recv(4096)
                    if not data:
                        why = "emulator closed"
                        break
                    outbound += len(data)
                    if outbound > self.max_outbound:
                        why = "outbound cap"
                        break
                    up.sendall(data)
                    self._capture(session, "out", data)
                if up in ready:
                    data = up.recv(4096)
                    if not data:
                        why = "remote closed"
                        break
                    inbound += len(data)
                    if inbound > self.max_inbound:
                        why = "inbound cap"
                        break
                    client.sendall(data)
                    raw.write(data)
                    raw.flush()
                    self._capture(session, "in", data)
        except OSError as e:  # a reset/broken pipe on either side ends the session cleanly
            why = f"socket error: {type(e).__name__}"
        finally:
            raw.close()
        self._capture(session, "closed", note=f"{why}; in={inbound} out={outbound}")

    def serve(self, socket_path: str) -> None:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(socket_path)
        os.chmod(socket_path, 0o600)
        srv.listen(8)
        srv.settimeout(0.5)
        print(f"relay listening on {socket_path}; allow={sorted(self.allow)}; "
              f"max_sessions={self.max_sessions}", flush=True)
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()
        finally:
            srv.close()
            if os.path.exists(socket_path):
                os.unlink(socket_path)

    def stop(self) -> None:
        self._stop.set()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--socket", required=True)
    sv.add_argument("--allow", action="append", required=True, help="ip:port (repeatable)")
    sv.add_argument("--capture", required=True)
    sv.add_argument("--max-sessions", type=int, default=5)
    sv.add_argument("--max-session-seconds", type=float, default=60.0)
    sv.add_argument("--max-inbound", type=int, default=1 << 20)
    sv.add_argument("--allow-private", action="store_true", help="tests only")
    a = ap.parse_args()
    RelayServer(set(a.allow), a.capture, max_sessions=a.max_sessions,
                max_session_seconds=a.max_session_seconds, max_inbound=a.max_inbound,
                allow_private=a.allow_private).serve(a.socket)


if __name__ == "__main__":
    main()
