"""Builds tiny synthetic i386 Linux ELF executables for tests.

Everything here is hand-assembled from a handful of opcodes (mov reg,imm32 / int 0x80 /
jumps). These are inert test fixtures for the emulator -- never real malware -- and use only
RFC 5737 documentation addresses and ``.test`` hostnames.
"""
from __future__ import annotations

import struct

BASE = 0x08048000
CODE_OFF = 0x100
DATA_OFF = 0x1000
EBX, ECX, EDX, ESI, EDI, EBP = 3, 1, 2, 6, 7, 5
_ARG_REGS = (EBX, ECX, EDX, ESI, EDI, EBP)


class Prog:
    base = BASE          # load address; subclasses for other ABIs override it
    endian = "<"         # byte order of the guest

    def __init__(self) -> None:
        self.code = bytearray()
        self.data = bytearray()
        self.labels: dict = {}
        self.fixups: list = []

    # -- data ---------------------------------------------------------------
    def d(self, blob: bytes) -> int:
        """Place ``blob`` in the data area (4-byte aligned) and return its address."""
        while len(self.data) % 4:
            self.data.append(0)
        addr = self.base + DATA_OFF + len(self.data)
        self.data += blob
        return addr

    def cstr(self, s: str) -> int:
        return self.d(s.encode() + b"\0")

    def ptrs(self, *values: int) -> int:
        return self.d(struct.pack(f"{self.endian}{len(values)}I", *values))

    @classmethod
    def sockaddr_in(cls, ip: str, port: int) -> bytes:
        return (struct.pack(cls.endian + "H", 2) + struct.pack(">H", port)
                + bytes(int(o) for o in ip.split(".")) + b"\0" * 8)

    # -- code ---------------------------------------------------------------
    @property
    def here(self) -> int:
        return self.base + CODE_OFF + len(self.code)

    def raw(self, b: bytes) -> None:
        self.code += b

    def mov(self, reg: int, imm: int) -> None:
        self.code += bytes([0xB8 + reg]) + struct.pack("<I", imm & 0xFFFFFFFF)

    def sys(self, nr: int, *args: int) -> None:
        for reg, val in zip(_ARG_REGS, args):
            self.mov(reg, val)
        self.mov(0, nr)
        self.code += b"\xcd\x80"

    def ebx_from_eax(self) -> None:
        self.code += b"\x89\xc3"  # mov ebx, eax

    def store_eax(self, addr: int) -> None:
        self.code += b"\xa3" + struct.pack("<I", addr)  # mov [addr], eax

    def poke_byte(self, addr: int, value: int) -> None:
        self.code += b"\xc6\x05" + struct.pack("<I", addr) + bytes([value])  # mov byte [addr], imm8

    def edx_from_eax(self) -> None:
        self.code += b"\x89\xc2"  # mov edx, eax

    def label(self, name: str) -> None:
        self.labels[name] = self.here

    def jmp(self, name: str) -> None:
        self.code += b"\xe9\0\0\0\0"
        self.fixups.append((len(self.code) - 4, name))

    def loop_dec(self, counter_addr: int, name: str) -> None:
        """dec dword [counter_addr]; jnz name  (a guest-side loop without unrolling code)."""
        self.code += b"\xff\x0d" + struct.pack("<I", counter_addr) + b"\x0f\x85\0\0\0\0"
        self.fixups.append((len(self.code) - 4, name))

    def jnz(self, name: str) -> None:
        self.code += b"\x85\xc0\x0f\x85\0\0\0\0"  # test eax,eax ; jnz rel32
        self.fixups.append((len(self.code) - 4, name))

    def exit(self, code: int = 0) -> None:
        self.sys(1, code)

    # -- output -------------------------------------------------------------
    def build(self, machine: int = 3, flags: int = 0) -> bytes:
        assert len(self.code) <= DATA_OFF - CODE_OFF, "code overflows into the data area"
        for pos, name in self.fixups:
            target = self.labels[name]
            after = self.base + CODE_OFF + pos + 4
            self.code[pos:pos + 4] = struct.pack("<i", target - after)
        blob = bytearray(DATA_OFF + len(self.data))
        blob[CODE_OFF:CODE_OFF + len(self.code)] = self.code
        blob[DATA_OFF:] = self.data
        e = self.endian
        ehdr = (b"\x7fELF" + bytes([1, 1 if e == "<" else 2, 1, 0]) + b"\0" * 8
                + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, self.base + CODE_OFF, 52, 0, flags,
                              52, 32, 1, 0, 0, 0))
        phdr = struct.pack(e + "8I", 1, 0, self.base, self.base, len(blob), len(blob) + 0x2000, 7, 0x1000)
        blob[0:52] = ehdr
        blob[52:84] = phdr
        return bytes(blob)
