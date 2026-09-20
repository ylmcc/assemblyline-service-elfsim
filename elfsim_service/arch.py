"""Per-architecture description of how a Linux userland binary talks to its kernel.

ElfSim never executes a sample on the real CPU: Unicorn interprets its instructions and
every system call is answered by our own fake kernel (kernel.py). This module is just the
table that lets the same fake kernel serve different CPU architectures -- which register
carries the syscall number/arguments/return value, what interrupt number Unicorn reports
for the syscall instruction, and the syscall-number -> name table.
"""
from __future__ import annotations

from dataclasses import dataclass

from unicorn import UC_ARCH_X86, UC_MODE_32
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

ARCHES = {a.e_machine: a for a in (I386,)}
