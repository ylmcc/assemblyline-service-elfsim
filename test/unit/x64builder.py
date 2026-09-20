"""Builds tiny synthetic x86-64 Linux ELF executables for tests (ELF64, static, non-PIE).

Inert fixtures hand-assembled from a handful of opcodes (movabs, syscall, jumps, small stores).
No real malware; documentation addresses and .test hostnames only. Only ever emulated.
"""
from __future__ import annotations

import struct

from elfsim_service.arch import X86_64
from test.unit.elfbuilder import CODE_OFF, DATA_OFF, Prog

RAX, RCX, RDX, RBX, RSI, RDI, R8, R9, R10 = 0, 1, 2, 3, 6, 7, 8, 9, 10
_ARG_REGS = (RDI, RSI, RDX, R10, R8, R9)
_NR = {name: number for number, name in X86_64.syscalls.items()}
BASE64 = 0x400000


class X64Prog(Prog):
    base = BASE64

    def mov(self, reg: int, imm: int) -> None:
        """movabs reg, imm64"""
        rex = 0x48 | (1 if reg >= 8 else 0)
        self.code += bytes([rex, 0xB8 + (reg & 7)]) + struct.pack("<Q", imm & 0xFFFFFFFFFFFFFFFF)

    def sys(self, nr: int, *args: int) -> None:
        for reg, val in zip(_ARG_REGS, args):
            self.mov(reg, val)
        self.mov(RAX, nr)
        self.code += b"\x0f\x05"                       # syscall

    def call(self, name: str, *args: int) -> None:
        self.sys(_NR[name], *args)

    def call_keep_args(self, name: str) -> None:
        self.mov(RAX, _NR[name])
        self.code += b"\x0f\x05"

    def exit(self, code: int = 0) -> None:
        self.call("exit", code)

    def ptrs(self, *values: int) -> int:
        return self.d(struct.pack(f"<{len(values)}Q", *values))     # 8-byte pointers

    def rdi_from_rax(self) -> None:
        self.code += b"\x48\x89\xc7"                   # mov rdi, rax

    def rdx_from_rax(self) -> None:
        self.code += b"\x48\x89\xc2"                   # mov rdx, rax

    def store_rax(self, addr: int) -> None:
        self.mov(RBX, addr)
        self.code += b"\x48\x89\x03"                   # mov [rbx], rax

    def load_stack_word(self, offset: int) -> None:
        self.code += b"\x48\x8b\x44\x24" + bytes([offset])           # mov rax, [rsp+offset]

    def spin_until_nonzero(self, addr: int) -> None:
        self.mov(RBX, addr)
        self.code += b"\x83\x3b\x00\x74\xfb"      # L: cmp dword [rbx], 0 ; je L

    def load_fs0(self) -> None:
        self.code += b"\x64\x48\x8b\x04\x25\x00\x00\x00\x00"   # mov rax, fs:[0]

    def poke_byte(self, addr: int, value: int) -> None:
        self.mov(RBX, addr)
        self.code += b"\xc6\x03" + bytes([value])      # mov byte [rbx], imm8

    def jnz(self, name: str) -> None:
        self.code += b"\x48\x85\xc0\x0f\x85\0\0\0\0"   # test rax,rax ; jnz rel32
        self.fixups.append((len(self.code) - 4, name))

    def loop_dec(self, counter_addr: int, name: str) -> None:
        self.mov(RBX, counter_addr)
        self.code += b"\xff\x0b\x0f\x85\0\0\0\0"       # dec dword [rbx] ; jnz rel32
        self.fixups.append((len(self.code) - 4, name))

    def build(self, machine: int = 62, flags: int = 0) -> bytes:
        for pos, name in self.fixups:
            after = self.base + CODE_OFF + pos + 4
            self.code[pos:pos + 4] = struct.pack("<i", self.labels[name] - after)
        assert len(self.code) <= DATA_OFF - CODE_OFF, "code overflows into the data area"
        blob = bytearray(DATA_OFF + len(self.data))
        blob[CODE_OFF:CODE_OFF + len(self.code)] = self.code
        blob[DATA_OFF:] = self.data
        ehdr = (b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
                + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, self.base + CODE_OFF, 64, 0, flags,
                              64, 56, 1, 0, 0, 0))
        phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, self.base, self.base, len(blob),
                           len(blob) + 0x2000, 0x1000)
        blob[0:64] = ehdr
        blob[64:120] = phdr
        return bytes(blob)
