"""Builds tiny synthetic little-endian MIPS (o32) Linux ELF executables for tests.

Like elfbuilder.py these are inert fixtures hand-assembled from a handful of opcodes (lui/ori,
sw/sb/lw, bne/beq with their delay slots, syscall). No real malware; documentation addresses
and .test hostnames only. They are only ever emulated, never run.
"""
from __future__ import annotations

import struct

from elfsim_service.arch import MIPSEL
from test.unit.elfbuilder import BASE, CODE_OFF, Prog

ZERO, V0, V1, A0, A1, A2, A3, T0, T1, SP = 0, 2, 3, 4, 5, 6, 7, 8, 9, 29
_ARG_REGS = (A0, A1, A2, A3)
_NR = {name: number for number, name in MIPSEL.syscalls.items()}


class MipsProg(Prog):
    def __init__(self) -> None:
        super().__init__()
        self.branches: list = []   # (byte offset of the branch in .code, label)

    def _w(self, word: int) -> None:
        self.code += struct.pack(self.endian + "I", word & 0xFFFFFFFF)

    def li(self, reg: int, imm: int) -> None:
        imm &= 0xFFFFFFFF
        self._w(0x3C000000 | (reg << 16) | (imm >> 16))                        # lui reg, hi16
        self._w(0x34000000 | (reg << 21) | (reg << 16) | (imm & 0xFFFF))       # ori reg, reg, lo16

    def move(self, dst: int, src: int) -> None:
        self._w((src << 21) | (dst << 11) | 0x25)                              # or dst, src, $zero

    def sys(self, nr: int, *args: int) -> None:
        """Raw syscall by absolute number. Args 1-4 in $a0-$a3, 5-6 on the stack (o32)."""
        for i, val in enumerate(args):
            if i < 4:
                self.li(_ARG_REGS[i], val)
            else:
                self.li(T0, val)
                self._w(0xAC000000 | (SP << 21) | (T0 << 16) | (16 + 4 * (i - 4)))   # sw $t0, off($sp)
        self.li(V0, nr)
        self._w(0x0000000C)                                                    # syscall

    def call(self, name: str, *args: int) -> None:
        self.sys(_NR[name], *args)

    def call_keep_args(self, name: str) -> None:
        """Issue a syscall without touching $a0-$a3 (they hold values set up earlier)."""
        self.li(V0, _NR[name])
        self._w(0x0000000C)

    def exit(self, code: int = 0) -> None:
        self.call("exit", code)

    def fd_from_result(self) -> None:
        self.move(A0, V0)

    def store_reg(self, reg: int, addr: int) -> None:
        self.li(T0, addr)
        self._w(0xAC000000 | (T0 << 21) | (reg << 16))                         # sw reg, 0($t0)

    def poke_byte(self, addr: int, value: int) -> None:
        self.li(T0, addr)
        self.li(T1, value)
        self._w(0xA0000000 | (T0 << 21) | (T1 << 16))                          # sb $t1, 0($t0)

    def _branch(self, opcode_word: int, label: str) -> None:
        self.branches.append((len(self.code), label))
        self._w(opcode_word)
        self._w(0)                                                             # delay slot: nop

    def bnez_v0(self, label: str) -> None:
        self._branch(0x14400000, label)                                        # bne $v0, $zero, label

    def b(self, label: str) -> None:
        self._branch(0x10000000, label)                                        # beq $zero, $zero, label

    def loop_dec(self, counter_addr: int, label: str) -> None:
        self.li(T0, counter_addr)
        self._w(0x8C000000 | (T0 << 21) | (T1 << 16))                          # lw $t1, 0($t0)
        self._w(0x24000000 | (T1 << 21) | (T1 << 16) | 0xFFFF)                 # addiu $t1, $t1, -1
        self._w(0xAC000000 | (T0 << 21) | (T1 << 16))                          # sw $t1, 0($t0)
        self._branch(0x14000000 | (T1 << 21), label)                           # bne $t1, $zero, label

    def build(self, machine: int = 8, flags: int = 0x1000) -> bytes:
        for pos, label in self.branches:
            after = self.base + CODE_OFF + pos + 4
            offset = ((self.labels[label] - after) >> 2) & 0xFFFF
            word = struct.unpack_from(self.endian + "I", self.code, pos)[0] & 0xFFFF0000
            struct.pack_into(self.endian + "I", self.code, pos, word | offset)
        return super().build(machine=machine, flags=flags)


class MipsBEProg(MipsProg):
    """Big-endian MIPS: the same instructions and data, the other byte order."""
    endian = ">"
