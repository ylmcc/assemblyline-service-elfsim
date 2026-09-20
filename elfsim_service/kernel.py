"""A fake Linux kernel for ElfSim.

Every syscall a sample makes lands here and is answered from in-memory state: there is no
real filesystem, network, process table or clock behind it, so the sample can never affect
anything outside the emulator. The interesting calls (network, file, process) are recorded
in ``events`` so the service can report what the sample *tried* to do.
"""
from __future__ import annotations

import ipaddress
import random
import struct
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from unicorn import UC_PROT_ALL, UcError

from elfsim_service.arch import Arch

PAGE = 0x1000
MMAP_BASE = 0x40000000
MAX_EVENTS = 5000
MAX_SENT_ENTRIES = 200
MAX_SENT_BYTES = 256 * 1024
MAX_MESSAGES_PER_CONVERSATION = 60
MAX_MESSAGE_BYTES = 2048
MAX_STDOUT = 64 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 50
MAX_FORKS = 16
MAX_RECEIVED_ENTRIES = 200
MAX_RECEIVED_BYTES = 2 * 1024 * 1024
RELAY_MAX_WAIT = 2.0  # real seconds a select()/recv() will wait for relayed data
MAX_PATH_SYSCALLS = 20_000  # per forked path, so an idle daemon loop can't starve the parent path
MAX_MAPPED_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024  # per fork; larger address spaces are only partly restored

# DNS queries are answered with this documentation-range address (RFC 5737) so a bot that
# resolves its C2 by name carries on to the real connect() and we learn the port.
SINKHOLE_IP = "192.0.2.53"

EPERM, ENOENT, EBADF, EAGAIN, ENOMEM, EFAULT = 1, 2, 9, 11, 12, 14
ENODEV, EINVAL, ENOTTY, EFBIG, ENOSYS, EAFNOSUPPORT, EPIPE, ECONNREFUSED = 19, 22, 25, 27, 38, 97, 32, 111

O_ACCMODE, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND = 3, 1, 2, 0o100, 0o1000, 0o2000
MAP_FIXED, MAP_ANONYMOUS = 0x10, 0x20
CLONE_VM = 0x100
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW = 1, 2, 3
AF_UNIX, AF_INET, AF_NETLINK, AF_INET6 = 1, 2, 16, 10
POLLIN, POLLOUT = 1, 4
PR_SET_NAME = 15

# i386 socketcall() sub-call numbers -> the same names the direct syscalls use.
_SOCKETCALLS = {
    1: "socket", 2: "bind", 3: "connect", 4: "listen", 5: "accept", 6: "getsockname",
    7: "getpeername", 8: "socketpair", 9: "send", 10: "recv", 11: "sendto",
    12: "recvfrom", 13: "shutdown", 14: "setsockopt", 15: "getsockopt", 16: "sendmsg",
    17: "recvmsg", 18: "accept4",
}

# Directories that exist in the fake filesystem, so probes for a writable working directory
# (a common first step in loaders) behave like a normal Linux box instead of failing.
FAKE_DIRS = {
    "/", "/tmp", "/var", "/var/tmp", "/var/run", "/run", "/mnt", "/root", "/opt", "/home",
    "/dev", "/dev/shm", "/proc", "/sys", "/bin", "/sbin", "/usr", "/usr/bin", "/etc",
}
# Read-only files the sample may read; served from memory, never reported as dropped.
STATIC_FILES = {
    "/proc/mounts": b"rootfs / rootfs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n",
    "/proc/cpuinfo": b"processor\t: 0\nmodel name\t: emulated\n",
    "/proc/version": b"Linux version 3.2.0 (emulated)\n",
}

# Syscalls seen constantly and never interesting on their own: counted, not logged.
_QUIET = {
    "brk", "mmap", "mmap2", "munmap", "mprotect", "gettimeofday", "time", "clock_gettime",
    "getpid", "getppid", "gettid", "getuid", "getuid32", "getgid32", "geteuid32",
    "getegid32", "sigaction", "rt_sigaction", "rt_sigprocmask", "signal", "sigreturn",
    "rt_sigreturn", "sched_yield", "futex", "set_tid_address", "set_robust_list",
    "getrandom", "fcntl", "fcntl64", "ioctl", "close", "read", "select", "_newselect",
    "poll", "nanosleep", "lseek", "_llseek", "fstat", "fstat64", "getrlimit", "ugetrlimit",
    "setrlimit", "umask", "uname", "getcwd", "setsockopt", "getsockopt", "getsockname",
    "getpeername", "recv", "recvfrom", "dup", "dup2", "pipe", "getdents", "getdents64",
}


def s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


class Fault(Exception):
    """A guest pointer could not be read/written: the syscall returns -EFAULT."""


@dataclass
class OpenFile:
    path: str
    flags: int
    data: bytearray
    pos: int = 0


@dataclass
class Device:
    name: str  # "stdin" | "stdout" | "stderr" | "null" | "urandom"


@dataclass
class Sock:
    family: int
    type: int
    proto: int
    remote: Optional[dict] = None
    recv_queue: deque = field(default_factory=deque)
    relay: Optional[object] = None  # RelaySession when this stream is relayed to a real endpoint
    conversation: Optional[dict] = None  # ordered record of what was sent on this socket


@dataclass
class Pipe:
    buf: bytearray


class FakeKernel:
    def __init__(self, uc, arch: Arch, *, brk_base: int, stack_low: int,
                 max_syscalls: int = 200_000, max_path_syscalls: int = MAX_PATH_SYSCALLS,
                 relay=None, seed: int = 0x5EED) -> None:
        self.uc = uc
        self.arch = arch
        self.max_syscalls = max_syscalls
        self.max_path_syscalls = max_path_syscalls
        self.relay = relay  # optional RelayClient; None = fully simulated network
        self.received: list[dict] = []
        self._received_bytes = 0
        self.path_syscalls = 0
        self.stack_low = stack_low
        self.rng = random.Random(seed)

        self.events: list[dict] = []
        self.events_dropped = 0
        self.counts: Counter = Counter()
        self.network: list[dict] = []
        self.files: dict[str, bytearray] = {}
        self.file_modes: dict[str, int] = {}
        self.stdout = bytearray()
        self.sent: list[dict] = []
        self._sent_bytes = 0
        self.unknown_syscalls: Counter = Counter()

        self.stop_reason: Optional[str] = None
        self.resume: Optional[dict] = None  # fork record to rewind to (the parent path)
        self._forks: list[dict] = []
        self._fork_total = 0
        self._next_pid = 1001
        self.syscall_count = 0

        self.pid, self.ppid = 1000, 1
        self.epoch = 1_700_000_000
        self.vtime = 0.0  # seconds slept so far; advances the fake clock
        self.cwd = "/"

        self.fds: dict[int, object] = {
            0: Device("stdin"), 1: Device("stdout"), 2: Device("stderr"),
        }
        self._missing_seen: set[str] = set()
        self.open_counts: Counter = Counter()

        self.brk_start = self.brk_cur = self.brk_mapped_end = _align_up(brk_base)
        self.mmap_next = MMAP_BASE
        self.mapped_bytes = 0

    # ---------------------------------------------------------------- plumbing
    def log(self, kind: str, name: str, **detail) -> None:
        if len(self.events) >= MAX_EVENTS:
            self.events_dropped += 1
            return
        self.events.append({"kind": kind, "syscall": name, **detail})

    def read(self, addr: int, n: int) -> bytes:
        try:
            return bytes(self.uc.mem_read(addr, n))
        except UcError:
            raise Fault(addr)

    def write(self, addr: int, data: bytes) -> None:
        try:
            self.uc.mem_write(addr, bytes(data))
        except UcError:
            raise Fault(addr)

    def cstr(self, addr: int, limit: int = 4096) -> str:
        out = bytearray()
        while len(out) < limit:
            chunk = self.read(addr + len(out), 1)
            if chunk == b"\0":
                break
            out += chunk
        return out.decode("latin-1")

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def put32(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def now(self) -> float:
        return self.epoch + self.vtime

    def _alloc_fd(self, obj) -> int:
        fd = 3
        while fd in self.fds:
            fd += 1
        self.fds[fd] = obj
        return fd

    def _map(self, addr: int, size: int) -> bool:
        size = _align_up(size)
        if self.mapped_bytes + size > MAX_MAPPED_BYTES:
            return False
        try:
            self.uc.mem_map(addr, size, UC_PROT_ALL)
        except UcError:
            return False
        self.mapped_bytes += size
        return True

    # ---------------------------------------------------------------- dispatch
    def handle(self) -> None:
        """Called from the interrupt hook when the guest executes its syscall instruction."""
        uc, arch = self.uc, self.arch
        nr = uc.reg_read(arch.nr_reg)
        args = [uc.reg_read(r) for r in arch.arg_regs]
        name = arch.syscalls.get(nr, f"sys_{nr}")

        self.syscall_count += 1
        self.counts[name] += 1
        if self.syscall_count > self.max_syscalls:
            self._stop("syscall_limit")
            return
        self.path_syscalls += 1
        if self._forks and self.path_syscalls > self.max_path_syscalls:
            self.abandon_path("syscall budget exhausted, likely an idle event loop")
            return

        handler: Optional[Callable] = getattr(self, f"sys_{name}", None)
        if handler is None:
            self.unknown_syscalls[name] += 1
            if self.unknown_syscalls[name] == 1:
                self.log("system", name, note="unimplemented syscall, returned -ENOSYS",
                         args=[hex(a) for a in args[:4]])
            ret = -ENOSYS
        else:
            try:
                ret = handler(*args)
            except Fault as f:
                ret = -EFAULT
                self.log("system", name, note=f"bad guest pointer {hex(f.args[0])}")
            except Exception as e:  # a handler bug must not take down the whole analysis
                ret = -ENOSYS
                self.log("system", name, note=f"internal error in handler: {type(e).__name__}: {e}")
        uc.reg_write(arch.ret_reg, ret & 0xFFFFFFFF)

    def _stop(self, reason: str) -> None:
        self.stop_reason = self.stop_reason or reason
        self.uc.emu_stop()

    def _snapshot(self) -> dict:
        regions, total = [], 0
        for begin, end, perms in self.uc.mem_regions():
            size = end - begin + 1
            total += size
            if total > MAX_SNAPSHOT_BYTES:
                break
            regions.append((begin, size, perms, bytes(self.uc.mem_read(begin, size))))
        return {"regions": regions, "fds": dict(self.fds), "brk_cur": self.brk_cur,
                "brk_mapped_end": self.brk_mapped_end, "mmap_next": self.mmap_next,
                "mapped_bytes": self.mapped_bytes, "cwd": self.cwd}

    def rewind(self, record: dict) -> int:
        """Restore the parent's CPU/memory/fd state from a fork record; return its resume pc."""
        snap = record["snap"]
        keep = {b: size for b, size, _, _ in snap["regions"]}
        for begin, end, _ in list(self.uc.mem_regions()):
            size = end - begin + 1
            if keep.get(begin) != size:   # mapped by the child (or resized): drop it
                try:
                    self.uc.mem_unmap(begin, size)
                except UcError:
                    pass
        present = {b: e - b + 1 for b, e, _ in self.uc.mem_regions()}
        for begin, size, perms, blob in snap["regions"]:
            if present.get(begin) != size:  # unmapped by the child: bring it back
                self.uc.mem_map(begin, size, perms)
            self.uc.mem_write(begin, blob)
        self.fds = dict(snap["fds"])
        self.brk_cur, self.brk_mapped_end = snap["brk_cur"], snap["brk_mapped_end"]
        self.mmap_next, self.mapped_bytes, self.cwd = snap["mmap_next"], snap["mapped_bytes"], snap["cwd"]
        self.uc.context_restore(record["ctx"])
        self.uc.reg_write(self.arch.ret_reg, record["pid"])
        self.path_syscalls = 0
        return self.uc.reg_read(self.arch.pc_reg)

    @property
    def has_pending_forks(self) -> bool:
        return bool(self._forks)

    def abandon_path(self, why: str) -> None:
        """Give up on the current forked path (it isn't finishing) and go back to its parent."""
        self.log("process", "fork", note=f"forked path abandoned: {why}",
                 syscalls_on_path=self.path_syscalls)
        self._end_process("path_abandoned")

    def _end_process(self, how: str) -> None:
        """The current (possibly forked-child) process is over: rewind to the parent if we
        forked, otherwise the whole emulation is finished."""
        if self._forks:
            self.resume = self._forks.pop()
            self.uc.emu_stop()
        else:
            self._stop(how)

    # ---------------------------------------------------------------- process
    def sys_exit(self, code, *_):
        self.log("process", "exit", code=s32(code))
        self._end_process(f"exit({s32(code)})")
        return 0

    sys_exit_group = sys_exit

    def sys_fork(self, *_):
        if self._fork_total >= MAX_FORKS:
            self.log("process", "fork", note="fork limit reached, returned -EAGAIN")
            return -EAGAIN
        self._fork_total += 1
        pid = self._next_pid
        self._next_pid += 1
        # Run the child path first; when it exits, execs or is abandoned we rewind to the
        # parent path so both halves of `if (fork() == 0) {...}` are explored. CPU state,
        # memory and the fd table are snapshotted and restored, as a real fork copies them.
        # The fake filesystem and network log stay shared, as they would be on a real box.
        self._forks.append({"ctx": self.uc.context_save(), "pid": pid, "snap": self._snapshot()})
        self.log("process", "fork", child_pid=pid)
        return 0

    sys_vfork = sys_fork

    def sys_clone(self, flags, *_):
        if flags & CLONE_VM:
            tid = self._next_pid
            self._next_pid += 1
            self.log("process", "clone", note="thread creation not emulated", flags=hex(flags))
            return tid
        return self.sys_fork()

    def sys_execve(self, path, argv, envp, *_):
        p = self.cstr(path)
        args = []
        for i in range(64):
            ptr = self.u32(argv + 4 * i) if argv else 0
            if not ptr:
                break
            args.append(self.cstr(ptr, 1024))
        self.log("process", "execve", path=p, argv=args)
        self._end_process("execve")
        return 0

    def sys_waitpid(self, pid, status_ptr, *_):
        if status_ptr:
            self.put32(status_ptr, 0)
        return self._next_pid - 1

    def sys_wait4(self, pid, status_ptr, *_):
        return self.sys_waitpid(pid, status_ptr)

    def sys_kill(self, pid, sig, *_):
        self.log("process", "kill", pid=s32(pid), signal=s32(sig))
        return 0

    def sys_getpid(self, *_):
        return self.pid

    def sys_gettid(self, *_):
        return self.pid

    def sys_getppid(self, *_):
        return self.ppid

    def sys_getuid(self, *_):
        return 0

    sys_getuid32 = sys_getgid32 = sys_geteuid32 = sys_getegid32 = sys_getuid

    def sys_setsid(self, *_):
        self.log("process", "setsid")
        return self.pid

    def sys_setpgid(self, *_):
        return 0

    def sys_getpgrp(self, *_):
        return self.pid

    def sys_setuid(self, *_):
        return 0

    def sys_prctl(self, option, arg2, *_):
        if option == PR_SET_NAME:
            self.log("process", "prctl", note="process renamed", new_name=self.cstr(arg2, 16))
        return 0

    def sys_ptrace(self, request, *_):
        # PTRACE_TRACEME is a common anti-debug probe; claim success so the sample proceeds.
        self.log("process", "ptrace", note="anti-debug probe", request=request)
        return 0

    def sys_set_tid_address(self, *_):
        return self.pid

    def sys_set_robust_list(self, *_):
        return 0

    def sys_futex(self, *_):
        return 0

    def sys_times(self, buf, *_):
        if buf:
            self.write(buf, b"\0" * 16)
        return int(self.vtime * 100) & 0x7FFFFFFF

    def sys_inotify_init(self, *_):
        return self._alloc_fd(Device("special"))

    sys_epoll_create = sys_inotify_init

    def sys_inotify_add_watch(self, *_):
        return 1

    def sys_inotify_rm_watch(self, *_):
        return 0

    def sys_sched_yield(self, *_):
        return 0

    # ---------------------------------------------------------------- signals
    def sys_sigaction(self, *_):
        return 0

    sys_rt_sigaction = sys_rt_sigprocmask = sys_signal = sys_sigaction
    sys_sigreturn = sys_rt_sigreturn = sys_sigaction

    def sys_alarm(self, *_):
        return 0

    def sys_pause(self, *_):
        self.vtime += 3600
        return -4  # EINTR

    # ---------------------------------------------------------------- time
    def sys_time(self, tptr, *_):
        t = int(self.now())
        if tptr:
            self.put32(tptr, t)
        return t

    def sys_gettimeofday(self, tv, *_):
        if tv:
            sec = self.now()
            self.write(tv, struct.pack("<II", int(sec), int((sec % 1) * 1_000_000)))
        return 0

    def sys_clock_gettime(self, clk, ts, *_):
        if ts:
            sec = self.now()
            self.write(ts, struct.pack("<II", int(sec), int((sec % 1) * 1e9)))
        return 0

    def sys_nanosleep(self, req, *_):
        if req:
            sec, nsec = struct.unpack("<II", self.read(req, 8))
            self.vtime += sec + nsec / 1e9
        return 0

    # ---------------------------------------------------------------- memory
    def sys_brk(self, addr, *_):
        if addr == 0 or addr < self.brk_start:
            return self.brk_cur
        new_end = _align_up(addr)
        if new_end > self.brk_mapped_end:
            if new_end >= MMAP_BASE or not self._map(self.brk_mapped_end,
                                                     new_end - self.brk_mapped_end):
                return self.brk_cur
            self.brk_mapped_end = new_end
        self.brk_cur = addr
        return self.brk_cur

    def _sys_mmap(self, addr, length, prot, flags, fd, offset):
        if length == 0:
            return -EINVAL
        size = _align_up(length)
        if flags & MAP_FIXED and addr % PAGE == 0:
            try:
                self.uc.mem_unmap(addr, size)
            except UcError:
                pass
            if not self._map(addr, size):
                return -ENOMEM
            base = addr
        else:
            if self.mmap_next + size >= self.stack_low:
                return -ENOMEM
            if not self._map(self.mmap_next, size):
                return -ENOMEM
            base = self.mmap_next
            self.mmap_next += size
        if not flags & MAP_ANONYMOUS and s32(fd) != -1:
            obj = self.fds.get(s32(fd))
            if isinstance(obj, OpenFile):
                self.write(base, bytes(obj.data[offset:offset + length]))
            elif isinstance(obj, Device) and obj.name == "urandom":
                self.write(base, self._random(length))
            else:
                return -EBADF
        return base

    def sys_mmap2(self, addr, length, prot, flags, fd, pgoff):
        return self._sys_mmap(addr, length, prot, flags, fd, pgoff * PAGE)

    def sys_mmap(self, ptr, *_):
        # old i386 mmap(): a single pointer to an argument block
        a = struct.unpack("<6I", self.read(ptr, 24))
        return self._sys_mmap(*a)

    def sys_munmap(self, addr, length, *_):
        try:
            self.uc.mem_unmap(addr & ~(PAGE - 1), _align_up(length))
            self.mapped_bytes = max(0, self.mapped_bytes - _align_up(length))
        except UcError:
            pass
        return 0

    def sys_mprotect(self, *_):
        return 0  # every mapping is already RWX

    # ---------------------------------------------------------------- misc info
    def _random(self, n: int) -> bytes:
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    def sys_getrandom(self, buf, n, *_):
        self.write(buf, self._random(n))
        return n

    def sys_uname(self, buf, *_):
        fields = [b"Linux", b"localhost", b"3.2.0", b"#1 SMP", b"i686", b"(none)"]
        self.write(buf, b"".join(f.ljust(65, b"\0") for f in fields))
        return 0

    def sys_sysinfo(self, buf, *_):
        self.write(buf, struct.pack("<11I", 86400, 0, 0, 0, 512 * 1024 * 1024,
                                    256 * 1024 * 1024, 0, 0, 0, 0, 1) + b"\0" * 20)
        return 0

    def sys_getrlimit(self, res, buf, *_):
        self.write(buf, struct.pack("<II", 0x7FFFFFFF, 0x7FFFFFFF))
        return 0

    sys_ugetrlimit = sys_getrlimit

    def sys_setrlimit(self, *_):
        return 0

    def sys_umask(self, *_):
        return 0o22

    def sys_getcwd(self, buf, size, *_):
        data = self.cwd.encode() + b"\0"
        if len(data) > size:
            return -34  # ERANGE
        self.write(buf, data)
        return len(data)

    def sys_ioctl(self, *_):
        return -ENOTTY

    def sys_fcntl(self, fd, cmd, *_):
        return 0

    sys_fcntl64 = sys_fcntl

    def sys_set_thread_area(self, *_):
        return -ENOSYS  # TLS setup: only needed if a real sample proves it necessary

    # ---------------------------------------------------------------- files
    def _norm(self, path: str) -> str:
        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path
        return path

    def _open(self, path: str, flags: int) -> int:
        path = self._norm(path)
        self.open_counts[path] += 1
        if path in ("/dev/urandom", "/dev/random"):
            return self._alloc_fd(Device("urandom"))
        if path in ("/dev/null", "/dev/zero"):
            return self._alloc_fd(Device("null"))
        if path in FAKE_DIRS:
            return self._alloc_fd(Device("dir"))
        if path in STATIC_FILES and path not in self.files:
            return self._alloc_fd(OpenFile(path, flags, bytearray(STATIC_FILES[path])))
        if path.startswith("/dev/") or path.startswith("/proc/") or path.startswith("/sys/"):
            if path not in self._missing_seen and len(self._missing_seen) < 200:
                self._missing_seen.add(path)
                self.log("file", "open", path=path, note="special file opened", flags=oct(flags))
            return self._alloc_fd(Device("special"))
        writing = flags & (O_WRONLY | O_RDWR) or flags & O_CREAT
        if path in self.files or writing:
            if path not in self.files:
                if len(self.files) >= MAX_FILES:
                    return -ENOMEM
                self.files[path] = bytearray()
                self.log("file", "open", path=path, note="created", flags=oct(flags))
            elif flags & O_TRUNC:
                self.files[path] = bytearray()
            content = self.files[path]
            return self._alloc_fd(OpenFile(path, flags, content, len(content) if flags & O_APPEND else 0))
        if path not in self._missing_seen and len(self._missing_seen) < 200:
            self._missing_seen.add(path)
            self.log("file", "open", path=path, note="probed, does not exist")
        return -ENOENT

    def sys_open(self, path, flags, mode, *_):
        return self._open(self.cstr(path), flags)

    def sys_openat(self, dirfd, path, flags, *_):
        return self._open(self.cstr(path), flags)

    def sys_creat(self, path, mode, *_):
        return self._open(self.cstr(path), O_CREAT | O_WRONLY | O_TRUNC)

    def sys_close(self, fd, *_):
        return 0 if self.fds.pop(s32(fd), None) is not None else -EBADF

    def sys_read(self, fd, buf, n, *_):
        obj = self.fds.get(s32(fd))
        n = min(n, 1 << 20)
        if isinstance(obj, Device):
            if obj.name == "dir":
                return -21  # EISDIR
            if obj.name != "urandom":
                return 0  # stdin, /dev/null and other special files read as immediate EOF
            data = self._random(n)
        elif isinstance(obj, OpenFile):
            data = bytes(obj.data[obj.pos:obj.pos + n])
            obj.pos += len(data)
        elif isinstance(obj, Sock):
            if obj.relay is not None and not obj.recv_queue:
                data = self._relay_recv(obj, n)
                if data is None:
                    return -EAGAIN
            elif obj.recv_queue:
                data = self._pop_queue(obj, n)
            else:
                return 0 if obj.type == SOCK_STREAM else -EAGAIN
        elif isinstance(obj, Pipe):
            data = bytes(obj.buf[:n])
            del obj.buf[:n]
        else:
            return -EBADF
        self.write(buf, data)
        return len(data)

    def _relay_recv(self, sock: Sock, n: int) -> Optional[bytes]:
        """Receive from a relayed stream, really waiting (bounded) like a blocking recv would."""
        data = sock.relay.recv(n)
        if data is None:
            self.vtime += self.relay.wait_any([sock.relay], RELAY_MAX_WAIT)
            data = sock.relay.recv(n)
        if data:  # keep what the remote end sent: this is the intel the relay exists for
            if len(self.received) < MAX_RECEIVED_ENTRIES and self._received_bytes < MAX_RECEIVED_BYTES:
                self._received_bytes += len(data)
                remote = sock.remote or {}
                self.received.append({"ip": remote.get("ip"), "port": remote.get("port"), "data": data})
        return data

    @staticmethod
    def _pop_queue(sock: Sock, n: int) -> bytes:
        chunk = sock.recv_queue.popleft()
        if len(chunk) > n:
            sock.recv_queue.appendleft(chunk[n:])
            chunk = chunk[:n]
        return chunk

    def sys_write(self, fd, buf, n, *_):
        obj = self.fds.get(s32(fd))
        if obj is None:
            return -EBADF
        data = self.read(buf, min(n, 1 << 20))
        return self._write_obj(s32(fd), obj, data)

    def _write_obj(self, fd: int, obj, data: bytes) -> int:
        if isinstance(obj, Device):
            if obj.name in ("stdout", "stderr") and len(self.stdout) < MAX_STDOUT:
                self.stdout += data[: MAX_STDOUT - len(self.stdout)]
            return len(data)
        if isinstance(obj, OpenFile):
            content = obj.data
            if obj.pos + len(data) > MAX_FILE_BYTES:
                return -EFBIG
            if obj.pos > len(content):
                content.extend(b"\0" * (obj.pos - len(content)))
            content[obj.pos:obj.pos + len(data)] = data
            obj.pos += len(data)
            return len(data)
        if isinstance(obj, Sock):
            return self._send(obj, data, None)
        if isinstance(obj, Pipe):
            obj.buf += data
            return len(data)
        return -EBADF

    def sys_writev(self, fd, iov, iovcnt, *_):
        obj = self.fds.get(s32(fd))
        if obj is None:
            return -EBADF
        total = 0
        for i in range(min(iovcnt, 64)):
            base, length = struct.unpack("<II", self.read(iov + 8 * i, 8))
            r = self._write_obj(s32(fd), obj, self.read(base, min(length, 1 << 20)))
            if r < 0:
                return r
            total += r
        return total

    def sys_lseek(self, fd, offset, whence, *_):
        obj = self.fds.get(s32(fd))
        if not isinstance(obj, OpenFile):
            return -EBADF if obj is None else -29  # ESPIPE
        size = len(obj.data)
        base = {0: 0, 1: obj.pos, 2: size}.get(whence)
        if base is None:
            return -EINVAL
        obj.pos = max(0, base + s32(offset))
        return obj.pos

    def sys__llseek(self, fd, hi, lo, result, whence, *_):
        r = self.sys_lseek(fd, lo, whence)
        if r >= 0:
            self.write(result, struct.pack("<Q", r))
            return 0
        return r

    def sys_unlink(self, path, *_):
        p = self._norm(self.cstr(path))
        existed = p in self.files
        self.log("file", "unlink", path=p, existed=existed)
        self.files.pop(p, None)
        return 0

    def sys_chmod(self, path, mode, *_):
        p = self._norm(self.cstr(path))
        self.log("file", "chmod", path=p, mode=oct(mode), existed=p in self.files)
        if p in self.files:
            self.file_modes[p] = mode
            return 0
        return -ENOENT

    def sys_rename(self, old, new, *_):
        o, n = self._norm(self.cstr(old)), self._norm(self.cstr(new))
        self.log("file", "rename", src=o, dst=n)
        if o in self.files:
            self.files[n] = self.files.pop(o)
            if o in self.file_modes:
                self.file_modes[n] = self.file_modes.pop(o)
            return 0
        return -ENOENT

    def sys_mkdir(self, path, *_):
        self.log("file", "mkdir", path=self._norm(self.cstr(path)))
        return 0

    sys_rmdir = sys_mkdir

    def sys_chdir(self, path, *_):
        self.cwd = self._norm(self.cstr(path))
        return 0

    def sys_access(self, path, *_):
        p = self._norm(self.cstr(path))
        known = p in self.files or p in FAKE_DIRS or p in STATIC_FILES or p.startswith("/dev/")
        return 0 if known else -ENOENT

    def sys_readlink(self, *_):
        return -ENOENT

    def _fill_stat(self, buf: int, mode: int, size: int, is64: bool) -> None:
        if is64:  # i386 struct stat64, 96 bytes
            raw = bytearray(96)
            struct.pack_into("<I", raw, 16, mode)
            struct.pack_into("<Q", raw, 44, size)
        else:     # old i386 struct stat, 64 bytes
            raw = bytearray(64)
            struct.pack_into("<H", raw, 8, mode & 0xFFFF)
            struct.pack_into("<I", raw, 20, size)
        self.write(buf, bytes(raw))

    def _stat_path(self, path_ptr: int, buf: int, is64: bool) -> int:
        p = self._norm(self.cstr(path_ptr))
        if p in self.files:
            self._fill_stat(buf, 0o100000 | self.file_modes.get(p, 0o644),
                            len(self.files[p]), is64)
            return 0
        if p in FAKE_DIRS:
            self._fill_stat(buf, 0o040755, 0, is64)
            return 0
        if p in STATIC_FILES:
            self._fill_stat(buf, 0o100444, len(STATIC_FILES[p]), is64)
            return 0
        if p.startswith("/dev/"):
            self._fill_stat(buf, 0o020666, 0, is64)
            return 0
        return -ENOENT

    def sys_stat64(self, path, buf, *_):
        return self._stat_path(path, buf, True)

    sys_lstat64 = sys_stat64

    def sys_stat(self, path, buf, *_):
        return self._stat_path(path, buf, False)

    sys_lstat = sys_stat

    def _fstat(self, fd: int, buf: int, is64: bool) -> int:
        obj = self.fds.get(s32(fd))
        if obj is None:
            return -EBADF
        if isinstance(obj, OpenFile):
            mode, size = 0o100000 | self.file_modes.get(obj.path, 0o644), len(obj.data)
        elif isinstance(obj, Device) and obj.name == "dir":
            mode, size = 0o040755, 0
        elif isinstance(obj, Sock):
            mode, size = 0o140000, 0
        else:
            mode, size = 0o020666, 0
        self._fill_stat(buf, mode, size, is64)
        return 0

    def sys_fstat64(self, fd, buf, *_):
        return self._fstat(fd, buf, True)

    def sys_fstat(self, fd, buf, *_):
        return self._fstat(fd, buf, False)

    def sys_getdents(self, *_):
        return 0

    sys_getdents64 = sys_getdents

    def sys_dup(self, fd, *_):
        obj = self.fds.get(s32(fd))
        return self._alloc_fd(obj) if obj is not None else -EBADF

    def sys_dup2(self, old, new, *_):
        obj = self.fds.get(s32(old))
        if obj is None:
            return -EBADF
        self.fds[s32(new)] = obj
        return new

    def sys_pipe(self, ptr, *_):
        pipe = Pipe(bytearray())
        self.write(ptr, struct.pack("<II", self._alloc_fd(pipe), self._alloc_fd(pipe)))
        return 0

    # ---------------------------------------------------------------- sockets
    def sys_socketcall(self, call, argp, *_):
        name = _SOCKETCALLS.get(call)
        if name is None:
            return -EINVAL
        n = 6 if name in ("sendto", "recvfrom") else 3
        args = list(struct.unpack(f"<{n}I", self.read(argp, 4 * n))) if argp else [0] * n
        args += [0] * (6 - len(args))
        self.counts[f"socketcall:{name}"] += 1
        handler = getattr(self, f"sys_{name}", None)
        return handler(*args) if handler else -ENOSYS

    def _parse_sockaddr(self, addr: int, alen: int) -> Optional[dict]:
        if not addr or alen < 2:
            return None
        raw = self.read(addr, min(alen, 128))
        family = struct.unpack_from("<H", raw)[0]
        if family == AF_INET and len(raw) >= 8:
            return {"family": "inet", "ip": ".".join(str(b) for b in raw[4:8]),
                    "port": struct.unpack_from(">H", raw, 2)[0]}
        if family == AF_INET6 and len(raw) >= 24:
            return {"family": "inet6", "ip": ipaddress.IPv6Address(bytes(raw[8:24])).compressed,
                    "port": struct.unpack_from(">H", raw, 2)[0]}
        if family == AF_UNIX:
            return {"family": "unix", "path": raw[2:].split(b"\0")[0].decode("latin-1")}
        return {"family": f"af_{family}"}

    def sys_socket(self, domain, typ, proto, *_):
        typ &= 0xF  # strip SOCK_NONBLOCK / SOCK_CLOEXEC
        if domain not in (AF_UNIX, AF_INET, AF_INET6, AF_NETLINK):
            return -EAFNOSUPPORT
        fd = self._alloc_fd(Sock(domain, typ, proto))
        if typ == SOCK_RAW:
            self.log("network", "socket", note="raw socket (flood/scan capability)",
                     family=domain, proto=proto)
        return fd

    def sys_connect(self, fd, addr, alen, *_):
        sock = self.fds.get(s32(fd))
        if not isinstance(sock, Sock):
            return -EBADF
        remote = self._parse_sockaddr(addr, alen)
        if remote is None:
            return -EFAULT
        sock.remote = remote
        if "ip" in remote:
            proto = "udp" if sock.type == SOCK_DGRAM else "tcp"
            self.network.append({"op": "connect", "proto": proto, **remote})
            if (proto == "tcp" and self.relay is not None
                    and self.relay.allows(remote["ip"], remote["port"])):
                session = self.relay.open(remote["ip"], remote["port"])
                if session is None:
                    self.log("network", "connect", proto=proto, relayed=False,
                             note="relay refused or unreachable", **remote)
                    return -ECONNREFUSED
                sock.relay = session
                self.log("network", "connect", proto=proto, relayed=True, **remote)
                return 0
            self.log("network", "connect", proto=proto, **remote)
        return 0  # otherwise always "succeeds" so the sample carries on to its next stage

    def sys_bind(self, fd, addr, alen, *_):
        sock = self.fds.get(s32(fd))
        if not isinstance(sock, Sock):
            return -EBADF
        local = self._parse_sockaddr(addr, alen)
        if local and "port" in local:
            proto = "udp" if sock.type == SOCK_DGRAM else "tcp"
            self.network.append({"op": "bind", "proto": proto, **local})
            self.log("network", "bind", proto=proto, **local)
        return 0

    def sys_listen(self, *_):
        return 0

    def sys_accept(self, *_):
        return -EAGAIN

    sys_accept4 = sys_accept

    def sys_shutdown(self, *_):
        return 0

    def sys_setsockopt(self, *_):
        return 0

    def sys_getsockopt(self, fd, level, opt, optval, optlen, *_):
        if optval:
            self.put32(optval, 0)  # e.g. SO_ERROR == 0: the connect "worked"
        if optlen:
            self.put32(optlen, 4)
        return 0

    def sys_getsockname(self, fd, addr, alenp, *_):
        if addr:
            self.write(addr, struct.pack("<HH", AF_INET, 0) + b"\0" * 12)
        if alenp:
            self.put32(alenp, 16)
        return 0

    sys_getpeername = sys_getsockname

    def _send(self, sock: Sock, data: bytes, dest: Optional[dict]) -> int:
        remote = dest or sock.remote or {}
        proto = "netlink" if sock.family == AF_NETLINK else "udp" if sock.type == SOCK_DGRAM else "tcp"
        if dest and "ip" in dest:
            self.network.append({"op": "sendto", "proto": proto, **dest})
            self.log("network", "sendto", proto=proto, **dest, bytes=len(data))
        self._record_sent(sock, proto, remote, data)
        if sock.relay is not None and dest is None:
            return len(data) if sock.relay.send(data) >= 0 else -EPIPE
        if proto == "udp" and remote.get("port") == 53:
            self._answer_dns(sock, data)
        return len(data)

    def _record_sent(self, sock: Sock, proto: str, remote: dict, data: bytes) -> None:
        """Keep what a socket sent as one ordered conversation. Consecutive identical writes are
        collapsed into a repeat count, so a heartbeat loop cannot push the interesting first
        messages (e.g. a C2 registration) out of the record."""
        ip, port = remote.get("ip"), remote.get("port")
        conv = sock.conversation
        if conv is None or (conv["ip"], conv["port"]) != (ip, port):
            if len(self.sent) >= MAX_SENT_ENTRIES:
                return
            conv = {"proto": proto, "ip": ip, "port": port, "messages": [], "total_bytes": 0}
            sock.conversation = conv
            self.sent.append(conv)
        conv["total_bytes"] += len(data)
        chunk = bytes(data[:MAX_MESSAGE_BYTES])
        messages = conv["messages"]
        if messages and messages[-1][0] == chunk:
            messages[-1][1] += 1
        elif (len(messages) < MAX_MESSAGES_PER_CONVERSATION
              and self._sent_bytes + len(chunk) <= MAX_SENT_BYTES):
            self._sent_bytes += len(chunk)
            messages.append([chunk, 1])

    def _answer_dns(self, sock: Sock, query: bytes) -> None:
        parsed = _parse_dns_query(query)
        if not parsed:
            return
        txid, qname, qtype, question = parsed
        self.network.append({"op": "dns_query", "proto": "udp", "domain": qname, "qtype": qtype})
        self.log("network", "dns_query", domain=qname, qtype=qtype)
        answer = b""
        ancount = 0
        if qtype == 1:  # A record: hand back the sinkhole address
            answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                      + bytes(int(o) for o in SINKHOLE_IP.split(".")))
            ancount = 1
        header = struct.pack(">HHHHHH", txid, 0x8180, 1, ancount, 0, 0)
        sock.recv_queue.append(header + question + answer)

    def sys_sendto(self, fd, buf, n, flags, addr, alen):
        sock = self.fds.get(s32(fd))
        if not isinstance(sock, Sock):
            return -EBADF
        dest = self._parse_sockaddr(addr, alen) if addr else None
        return self._send(sock, self.read(buf, min(n, 1 << 20)), dest)

    def sys_send(self, fd, buf, n, flags, *_):
        return self.sys_sendto(fd, buf, n, flags, 0, 0)

    def sys_sendmsg(self, fd, msg, flags, *_):
        sock = self.fds.get(s32(fd))
        if not isinstance(sock, Sock):
            return -EBADF
        name, namelen, iov, iovlen = struct.unpack("<IIII", self.read(msg, 16))
        data = b""
        for i in range(min(iovlen, 64)):
            base, length = struct.unpack("<II", self.read(iov + 8 * i, 8))
            data += self.read(base, min(length, 1 << 20))
        return self._send(sock, data, self._parse_sockaddr(name, namelen) if name else None)

    def sys_recvfrom(self, fd, buf, n, flags, addr, alenp):
        sock = self.fds.get(s32(fd))
        if not isinstance(sock, Sock):
            return -EBADF
        return self.sys_read(fd, buf, n)

    def sys_recv(self, fd, buf, n, flags, *_):
        return self.sys_recvfrom(fd, buf, n, flags, 0, 0)

    def sys_recvmsg(self, *_):
        return -EAGAIN

    def sys_socketpair(self, *_):
        return -EAFNOSUPPORT

    # ---------------------------------------------------------------- readiness
    def _readable(self, fd: int) -> bool:
        obj = self.fds.get(fd)
        if isinstance(obj, Sock):
            return bool(obj.recv_queue) or (obj.relay is not None and obj.relay.readable())
        if isinstance(obj, Pipe):
            return bool(obj.buf)
        return isinstance(obj, OpenFile) or (isinstance(obj, Device) and obj.name == "urandom")

    def _relay_idle_wait(self, read_fds, timeout_s: float) -> None:
        """If a relayed stream is being watched and nothing is readable yet, really wait for it
        (bounded) so a reply from the remote end isn't missed by racing ahead in virtual time."""
        relayed = [self.fds[fd].relay for fd in read_fds
                   if isinstance(self.fds.get(fd), Sock) and self.fds[fd].relay is not None
                   and not self.fds[fd].relay.closed]
        if relayed and not any(self._readable(fd) for fd in read_fds):
            self.vtime += self.relay.wait_any(relayed, min(timeout_s, RELAY_MAX_WAIT))

    def sys_poll(self, fds, nfds, timeout, *_):
        if self.relay is not None and s32(timeout) > 0:
            watch = []
            for i in range(min(nfds, 1024)):
                fd, events, _r = struct.unpack("<ihh", self.read(fds + 8 * i, 8))
                if fd >= 0 and events & POLLIN:
                    watch.append(fd)
            self._relay_idle_wait(watch, s32(timeout) / 1000)
        ready = 0
        for i in range(min(nfds, 1024)):
            fd, events, _rev = struct.unpack("<ihh", self.read(fds + 8 * i, 8))
            rev = 0
            if fd >= 0 and fd in self.fds:
                if events & POLLIN and self._readable(fd):
                    rev |= POLLIN
                if events & POLLOUT:
                    rev |= POLLOUT
            self.write(fds + 8 * i + 6, struct.pack("<h", rev))
            ready += 1 if rev else 0
        if not ready and s32(timeout) > 0:
            self.vtime += s32(timeout) / 1000
        return ready

    def sys__newselect(self, n, rfds, wfds, efds, timeout, *_):
        n = min(n, 1024)
        nlongs = (n + 31) // 32
        if self.relay is not None and timeout and rfds:
            sec, usec = struct.unpack("<II", self.read(timeout, 8))
            words = struct.unpack(f"<{nlongs}I", self.read(rfds, 4 * nlongs))
            watch = [fd for fd in range(n) if words[fd // 32] >> (fd % 32) & 1]
            self._relay_idle_wait(watch, sec + usec / 1e6)
        ready = 0
        for ptr, kind in ((rfds, "r"), (wfds, "w"), (efds, "e")):
            if not ptr:
                continue
            words = list(struct.unpack(f"<{nlongs}I", self.read(ptr, 4 * nlongs)))
            for fd in range(n):
                if not words[fd // 32] >> (fd % 32) & 1:
                    continue
                keep = (kind == "w" and fd in self.fds) or (kind == "r" and self._readable(fd))
                if keep:
                    ready += 1
                else:
                    words[fd // 32] &= ~(1 << (fd % 32))
            self.write(ptr, struct.pack(f"<{nlongs}I", *words))
        if not ready and timeout:
            sec, usec = struct.unpack("<II", self.read(timeout, 8))
            self.vtime += sec + usec / 1e6
        return ready

    def sys_select(self, ptr, *_):
        return self.sys__newselect(*struct.unpack("<5I", self.read(ptr, 20)))


def _align_up(v: int) -> int:
    return (v + PAGE - 1) & ~(PAGE - 1)


def _parse_dns_query(pkt: bytes):
    """Return (txid, qname, qtype, raw_question_section) for a standard single-question query."""
    if len(pkt) < 17:
        return None
    txid = struct.unpack_from(">H", pkt)[0]
    pos, labels = 12, []
    while pos < len(pkt):
        ln = pkt[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 or pos + 1 + ln > len(pkt):
            return None
        labels.append(pkt[pos + 1:pos + 1 + ln].decode("latin-1"))
        pos += 1 + ln
    else:
        return None
    if pos + 4 > len(pkt):
        return None
    qtype = struct.unpack_from(">H", pkt, pos)[0]
    return txid, ".".join(labels), qtype, pkt[12:pos + 4]
