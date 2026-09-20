"""Real network access for the emulated sample, used only when the submitter turns it on.

By default the emulator has no network stack at all: connects are recorded and answered from
memory. With ``allow_internet`` enabled, TCP connects and UDP datagrams to *public* addresses
are made for real, so the sample talks to its actual C2/download servers and whatever it
receives (commands, payloads) is captured. Addresses that are not public internet
(loopback, RFC 1918, link-local, cloud metadata, multicast...) are never reachable, so the
sample cannot use the emulator as a way into the cluster or LAN it runs on.
"""
from __future__ import annotations

import ipaddress
import select
import socket
import time
from typing import Optional


class LiveSession:
    """One real TCP stream."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.closed = False

    def send(self, data: bytes, ip: Optional[str] = None, port: Optional[int] = None) -> int:
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
        return self.closed or bool(select.select([self.sock], [], [], 0)[0])

    def recv(self, n: int) -> Optional[bytes]:
        """Bytes now available, b"" on EOF, or None if nothing has arrived yet."""
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


class LiveUdp(LiveSession):
    """A real UDP socket (DNS lookups and the like)."""

    def __init__(self, sock: socket.socket) -> None:
        super().__init__(sock)

    def send(self, data: bytes, ip: Optional[str] = None, port: Optional[int] = None) -> int:
        if self.closed:
            return -1
        try:
            self.sock.sendto(data, (ip, port))
            return len(data)
        except OSError:
            return -1

    def recv(self, n: int) -> Optional[bytes]:
        if self.closed or not self.readable():
            return None
        try:
            return self.sock.recvfrom(n)[0]
        except OSError:
            return None


class LiveNetwork:
    def __init__(self, connect_timeout: float = 6.0, allow_private: bool = False) -> None:
        self.connect_timeout = connect_timeout
        self.allow_private = allow_private   # tests only: lets a loopback server stand in for the internet
        self.sessions: list = []

    def allows(self, ip: str, port: int) -> bool:
        """Public internet addresses only."""
        if not 0 < port < 65536:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.allow_private:
            return True
        return addr.is_global and not addr.is_multicast   # multicast counts as "global" in Python

    def open(self, ip: str, port: int) -> Optional[LiveSession]:
        try:
            sock = socket.create_connection((ip, port), timeout=self.connect_timeout)
        except OSError:
            return None
        sock.settimeout(None)
        session = LiveSession(sock)
        self.sessions.append(session)
        return session

    def udp(self) -> LiveUdp:
        session = LiveUdp(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
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
