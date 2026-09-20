"""Builds tiny synthetic ARM (EABI, little-endian, ARM mode) Linux ELF executables for tests.

Inert fixtures hand-assembled from a handful of opcodes (movw/movt, svc, str, cmp, branches,
mrc, blx). No real malware; documentation addresses and .test hostnames only. Only ever emulated.
"""
from __future__ import annotations

import struct

from elfsim_service.arch import ARM
from test.unit.elfbuilder import CODE_OFF, DATA_OFF, Prog

_NR = {name: number for number, name in ARM.syscalls.items()}
ARM_BASE = 0x8000


class ArmProg(Prog):
    base = ARM_BASE

    def __init__(self) -> None:
        super().__init__()
        self.branches: list = []

    def _w(self, word: int) -> None:
        self.code += struct.pack("<I", word & 0xFFFFFFFF)

    def li(self, reg: int, imm: int) -> None:
        imm &= 0xFFFFFFFF
        lo, hi = imm & 0xFFFF, imm >> 16
        self._w(0xE3000000 | ((lo >> 12) << 16) | (reg << 12) | (lo & 0xFFF))          # movw
        self._w(0xE3400000 | ((hi >> 12) << 16) | (reg << 12) | (hi & 0xFFF))          # movt

    def sys(self, nr: int, *args: int) -> None:
        for i, val in enumerate(args):
            self.li(i, val)
        self.li(7, nr)
        self._w(0xEF000000)                                                            # svc #0

    def call(self, name: str, *args: int) -> None:
        self.sys(_NR[name], *args)

    def call_keep_args(self, name: str) -> None:
        self.li(7, _NR[name])
        self._w(0xEF000000)

    def exit(self, code: int = 0) -> None:
        self.call("exit", code)

    def store_r0(self, addr: int) -> None:
        self.li(1, addr)
        self._w(0xE5810000)                                                            # str r0, [r1]

    def raw_words(self, *words: int) -> None:
        for w in words:
            self._w(w)

    def _branch(self, word: int, label: str) -> None:
        self.branches.append((len(self.code), label))
        self._w(word)

    def bnez_r0(self, label: str) -> None:
        self._w(0xE3500000)                                                            # cmp r0, #0
        self._branch(0x1A000000, label)                                                # bne label

    def build(self, machine: int = 40, flags: int = 0x05000000) -> bytes:
        for pos, label in self.branches:
            offset = ((self.labels[label] - (self.base + CODE_OFF + pos + 8)) >> 2) & 0xFFFFFF
            word = struct.unpack_from("<I", self.code, pos)[0] & 0xFF000000
            struct.pack_into("<I", self.code, pos, word | offset)
        return super().build(machine=machine, flags=flags)
