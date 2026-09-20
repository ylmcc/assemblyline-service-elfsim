"""Per-architecture description of how a Linux userland binary talks to its kernel.

ElfSim never executes a sample on the real CPU: Unicorn interprets its instructions and
every system call is answered by our own fake kernel (kernel.py). This module is just the
table that lets the same fake kernel serve different CPU architectures -- which register
carries the syscall number/arguments/return value, what interrupt number Unicorn reports
for the syscall instruction, and the syscall-number -> name table.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from unicorn import UC_ARCH_MIPS, UC_ARCH_X86, UC_MODE_32, UC_MODE_LITTLE_ENDIAN, UC_MODE_MIPS32
from unicorn.mips_const import (
    UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3, UC_MIPS_REG_CP0_USERLOCAL,
    UC_MIPS_REG_PC, UC_MIPS_REG_SP, UC_MIPS_REG_T9, UC_MIPS_REG_V0, UC_MIPS_REG_V1,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDI,
    UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP,
)


@dataclass(frozen=True)
class Arch:
    name: str
    e_machine: str            # pyelftools' EM_* name
    uc_arch: int
    uc_mode: int
    pc_reg: int
    sp_reg: int
    nr_reg: int               # register holding the syscall number
    arg_regs: tuple           # registers holding syscall arguments 0..n
    ret_reg: int
    intr_no: int              # interrupt number Unicorn reports for the syscall instruction
    syscalls: dict            # number -> name
    word_size: int = 4
    # ---- ABI differences. Defaults describe Linux/i386; the fake kernel works in i386
    # ("canonical") constants and translates at the edges using these.
    stack_arg_offset: Optional[int] = None   # syscall args beyond len(arg_regs) live on the stack here
    error_flag_reg: Optional[int] = None     # MIPS: set to 1 on error, with +errno in ret_reg
    errno_map: dict = field(default_factory=dict)        # canonical errno -> this arch's errno
    sock_type_map: dict = field(default_factory=dict)    # this arch's SOCK_* -> canonical
    o_creat: int = 0o100
    o_trunc: int = 0o1000
    o_append: int = 0o2000
    map_anonymous: int = 0x20
    stat64: tuple = (16, 4, 44, 96)          # (mode offset, mode bytes, size offset, struct size)
    stat32: tuple = (8, 2, 20, 64)
    old_mmap_struct: bool = True             # mmap(2) takes one pointer to an argument block
    pipe_second_reg: Optional[int] = None    # MIPS returns pipe()'s 2nd fd in a register
    set_tls: Optional[Callable] = None       # set_thread_area(): install the TLS pointer
    entry_regs: dict = field(default_factory=dict)       # extra registers at entry ("entry" = pc)
    uname_machine: str = "i686"              # what uname(2) reports, which bots sometimes report onward
    stack_top: int = 0xC0000000              # top of the user stack
    user_limit: int = 0xBF000000             # highest usable user address (MIPS32: 0x7fffffff)


# i386 Linux syscall numbers (only names we handle or want readable in the trace; anything
# else is logged as "sys_<n>" and answered with -ENOSYS).
_I386_SYSCALLS = {
    1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 7: "waitpid",
    8: "creat", 10: "unlink", 11: "execve", 12: "chdir", 13: "time", 15: "chmod",
    19: "lseek", 20: "getpid", 21: "mount", 23: "setuid", 24: "getuid", 26: "ptrace",
    27: "alarm", 29: "pause", 33: "access", 37: "kill", 38: "rename", 39: "mkdir",
    40: "rmdir", 41: "dup", 42: "pipe", 43: "times", 45: "brk", 48: "signal", 54: "ioctl",
    55: "fcntl", 57: "setpgid", 60: "umask", 63: "dup2", 64: "getppid", 65: "getpgrp",
    66: "setsid", 67: "sigaction", 75: "setrlimit", 76: "getrlimit", 78: "gettimeofday",
    82: "select", 85: "readlink", 90: "mmap", 91: "munmap", 102: "socketcall",
    106: "stat", 107: "lstat", 108: "fstat", 114: "wait4", 116: "sysinfo", 118: "fsync",
    119: "sigreturn", 120: "clone", 122: "uname", 125: "mprotect", 140: "_llseek",
    141: "getdents", 142: "_newselect", 146: "writev", 158: "sched_yield",
    162: "nanosleep", 168: "poll", 190: "vfork", 172: "prctl", 173: "rt_sigreturn",
    174: "rt_sigaction", 175: "rt_sigprocmask", 183: "getcwd", 191: "ugetrlimit",
    192: "mmap2", 195: "stat64", 196: "lstat64", 197: "fstat64", 199: "getuid32",
    200: "getgid32", 201: "geteuid32", 202: "getegid32", 220: "getdents64",
    221: "fcntl64", 224: "gettid", 240: "futex", 243: "set_thread_area",
    252: "exit_group", 254: "epoll_create", 258: "set_tid_address", 265: "clock_gettime", 295: "openat",
    291: "inotify_init", 292: "inotify_add_watch", 293: "inotify_rm_watch", 311: "set_robust_list", 355: "getrandom", 359: "socket", 361: "bind", 362: "connect",
    363: "listen", 364: "accept4", 365: "getsockopt", 366: "setsockopt",
    367: "getsockname", 368: "getpeername", 369: "sendto", 370: "sendmsg",
    371: "recvfrom", 372: "recvmsg", 373: "shutdown",
}

I386 = Arch(
    name="x86",
    e_machine="EM_386",
    uc_arch=UC_ARCH_X86,
    uc_mode=UC_MODE_32,
    pc_reg=UC_X86_REG_EIP,
    sp_reg=UC_X86_REG_ESP,
    nr_reg=UC_X86_REG_EAX,
    arg_regs=(UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
              UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP),
    ret_reg=UC_X86_REG_EAX,
    intr_no=0x80,
    syscalls=_I386_SYSCALLS,
)

def _load_syscall_table(filename: str) -> dict:
    table = {}
    with open(os.path.join(os.path.dirname(__file__), filename)) as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                number, name = line.split()
                table[int(number)] = name
    return table


# Linux MIPS (o32 ABI, little-endian "mipsel"). Differences from i386 that matter here:
#   * syscall via the `syscall` instruction (Unicorn reports interrupt 17), number in $v0
#     (4000 + n), arguments in $a0-$a3 then on the stack at sp+16, sp+20
#   * result in $v0; on error $a3 = 1 and $v0 holds the POSITIVE errno
#   * different errno numbers above 34, socket types (STREAM=2, DGRAM=1), open/mmap flags,
#     and struct stat layouts
MIPSEL = Arch(
    name="mipsel",
    e_machine="EM_MIPS",
    uc_arch=UC_ARCH_MIPS,
    uc_mode=UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
    pc_reg=UC_MIPS_REG_PC,
    sp_reg=UC_MIPS_REG_SP,
    nr_reg=UC_MIPS_REG_V0,
    arg_regs=(UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3),
    ret_reg=UC_MIPS_REG_V0,
    intr_no=17,
    syscalls=_load_syscall_table("syscalls_mips_o32.txt"),
    stack_arg_offset=16,
    error_flag_reg=UC_MIPS_REG_A3,
    errno_map={38: 89, 97: 124, 111: 146, 115: 150},    # ENOSYS, EAFNOSUPPORT, ECONNREFUSED, EINPROGRESS
    sock_type_map={1: 2, 2: 1},                          # mips DGRAM=1/STREAM=2 -> canonical STREAM=1/DGRAM=2
    o_creat=0x100,
    o_trunc=0x200,
    o_append=0x8,
    map_anonymous=0x800,
    stat64=(24, 4, 56, 104),
    stat32=(20, 4, 48, 88),
    old_mmap_struct=False,
    pipe_second_reg=UC_MIPS_REG_V1,
    set_tls=lambda uc, addr: uc.reg_write(UC_MIPS_REG_CP0_USERLOCAL, addr),
    entry_regs={UC_MIPS_REG_T9: "entry"},
    uname_machine="mips",
    stack_top=0x7FFF0000,        # MIPS32 user space ends at 0x7fffffff; above is kernel (kseg0/1)
    user_limit=0x7EFF0000,
)

ARCHES = {a.e_machine: a for a in (I386, MIPSEL)}
