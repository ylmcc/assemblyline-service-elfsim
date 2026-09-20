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
LIVE_MAX_WAIT = 2.0  # real seconds a select()/recv() will wait for data from the real network
MAX_PATH_SYSCALLS = 20_000  # per forked path, so an idle daemon loop can't starve the parent path
MAX_MAPPED_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024  # per fork; larger address spaces are only partly restored

# DNS queries are answered with this documentation-range address (RFC 5737) so a bot that
# resolves its C2 by name carries on to the real connect() and we learn the port.
SINKHOLE_IP = "192.0.2.53"

EPERM, ENOENT, EBADF, EAGAIN, ENOMEM, EFAULT = 1, 2, 9, 11, 12, 14
ENODEV, EINVAL, ENOTTY, EFBIG, ENOSYS, EAFNOSUPPORT, EPIPE, ECONNREFUSED = 19, 22, 25, 27, 38, 97, 32, 111
ETIMEDOUT, EEXIST = 110, 17
EPOLLIN, EPOLLOUT, EPOLLET = 0x1, 0x4, 1 << 31
EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD = 1, 2, 3

O_ACCMODE, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND = 3, 1, 2, 0o100, 0o1000, 0o2000
MAP_FIXED, MAP_ANONYMOUS = 0x10, 0x20
CLONE_VM = 0x100
CLONE_THREAD, CLONE_SETTLS, CLONE_PARENT_SETTID = 0x10000, 0x80000, 0x100000
CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID = 0x200000, 0x1000000
MAX_THREADS = 64
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
class Thread:
    """One emulated thread. Threads are cooperative: the running one keeps the CPU until it blocks
    or yields, so nothing runs in parallel and results stay deterministic."""
    tid: int
    ctx: object = None                    # saved CPU context while not running
    state: str = "ready"                  # ready (running or runnable) | futex | sleep | dead
    wait_addr: Optional[int] = None
    wake_at: Optional[float] = None       # virtual-clock deadline for a timed wait/sleep
    pending_ret: Optional[int] = None     # value the blocked syscall returns when it resumes
    setup: Optional[dict] = None          # first-run register setup for a freshly cloned thread
    clear_tid: int = 0                    # CLONE_CHILD_CLEARTID / set_tid_address word
    seq: int = 0                          # order in which threads blocked (FIFO futex wake-up)
    restart: bool = False                 # woken by readiness: re-run the blocked syscall
    restart_nr: int = 0                   # ...whose syscall number was this


@dataclass
class EventFd:
    counter: int = 0


@dataclass
class Epoll:
    watch: dict = field(default_factory=dict)      # fd -> [event mask, user data]
    reported: set = field(default_factory=set)     # edge-triggered fds already reported as ready


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
    live: Optional[object] = None  # LiveSession/LiveUdp when this socket uses the real network
    live_peer: Optional[tuple] = None  # (ip, port) a live UDP socket last sent to
    peer: Optional[tuple] = None       # (ip, port) of the remote end, reported back by recvfrom()
    conversation: Optional[dict] = None  # ordered record of what was sent on this socket


@dataclass
class Pipe:
    buf: bytearray


class FakeKernel:
    def __init__(self, uc, arch: Arch, *, brk_base: int, stack_low: int,
                 max_syscalls: int = 200_000, max_path_syscalls: int = MAX_PATH_SYSCALLS,
                 live_net=None, seed: int = 0x5EED) -> None:
        self.uc = uc
        self.arch = arch
        self._bo = "<" if arch.little_endian else ">"   # byte order of guest memory
        self.max_syscalls = max_syscalls
        self.max_path_syscalls = max_path_syscalls
        self.live_net = live_net  # optional LiveNetwork; None = fully simulated network
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
        self.threads: list = [Thread(tid=self.pid)]
        self.cur: Thread = self.threads[0]
        self.switch_to: Optional[Thread] = None   # thread the run loop must activate next
        self.replan = False                       # run loop should recompute its time slice and continue
        self.threads_created = 0
        self._block_seq = 0
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
        self.reserved: list = []   # [start, end) PROT_NONE address-space reservations: no memory behind them

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
        return struct.unpack(self._bo + "I", self.read(addr, 4))[0]

    def put32(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack(self._bo + "I", value & 0xFFFFFFFF))

    # ---- word-size-aware access: 32- and 64-bit ABIs share every code path that uses these
    @property
    def _wfmt(self) -> str:
        return "Q" if self.arch.word_size == 8 else "I"

    def read_words(self, addr: int, n: int) -> tuple:
        return struct.unpack(f"{self._bo}{n}{self._wfmt}", self.read(addr, n * self.arch.word_size))

    def pack_words(self, *values: int) -> bytes:
        mask = (1 << (self.arch.word_size * 8)) - 1
        return struct.pack(f"{self._bo}{len(values)}{self._wfmt}", *(v & mask for v in values))

    def uptr(self, addr: int) -> int:
        """Read one pointer-sized value."""
        return self.read_words(addr, 1)[0]

    def put_uptr(self, addr: int, value: int) -> None:
        self.write(addr, self.pack_words(value))

    def _iovec(self, base: int, index: int) -> tuple:
        """(buffer address, length) of the index-th struct iovec (8 bytes on 32-bit, 16 on 64-bit)."""
        return self.read_words(base + 2 * self.arch.word_size * index, 2)

    def _read_timeval(self, addr: int) -> float:
        sec, usec = self.read_words(addr, 2)
        return sec + usec / 1e6

    def _read_timespec(self, addr: int) -> float:
        sec, nsec = self.read_words(addr, 2)
        return sec + nsec / 1e9

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

    # ---- address space: committed memory lives in Unicorn; PROT_NONE mmaps are only reserved here.
    # Runtimes such as Go reserve hundreds of GiB of address space up front and commit pieces
    # later, exactly as a real kernel lets them: a reservation costs nothing.
    def _mapped_ranges(self) -> list:
        return [(b, e + 1) for b, e, _ in self.uc.mem_regions()]

    def _blocker(self, addr: int, size: int) -> Optional[int]:
        """End of the first mapped/reserved range overlapping [addr, addr+size), else None."""
        end = addr + size
        ends = [e for s, e in self._mapped_ranges() + [tuple(r) for r in self.reserved] if s < end and addr < e]
        return max(ends) if ends else None

    def _reserve(self, addr: int, size: int) -> None:
        self.reserved.append([addr, addr + size])

    def _unreserve(self, addr: int, size: int) -> None:
        end, kept = addr + size, []
        for s, e in self.reserved:
            if e <= addr or s >= end:
                kept.append([s, e])
                continue
            if s < addr:
                kept.append([s, addr])
            if e > end:
                kept.append([end, e])
        self.reserved = kept

    def _unmap_range(self, addr: int, size: int) -> None:
        """Drop whatever is mapped or reserved in [addr, addr+size); partial overlaps are fine."""
        end = addr + size
        self._unreserve(addr, size)
        for s, e in self._mapped_ranges():
            lo, hi = max(s, addr), min(e, end)
            if lo < hi:
                try:
                    self.uc.mem_unmap(lo, hi - lo)
                    self.mapped_bytes = max(0, self.mapped_bytes - (hi - lo))
                except UcError:
                    pass

    def _commit_reserved(self, addr: int, size: int) -> bool:
        """mprotect() making reserved pages accessible: back them with real memory now."""
        end = addr + size
        for s, e in [tuple(r) for r in self.reserved]:
            lo, hi = max(s, addr), min(e, end)
            if lo < hi:
                self._unreserve(lo, hi - lo)
                if not self._map(lo, hi - lo):
                    return False
        return True

    def _pick_address(self, size: int) -> Optional[int]:
        cand = self.mmap_next
        while cand + size < self.stack_low:
            blocked = self._blocker(cand, size)
            if blocked is None:
                self.mmap_next = cand + size
                return cand
            cand = _align_up(blocked)
        return None

    # ---------------------------------------------------------------- dispatch
    def handle(self) -> None:
        """Called from the interrupt hook when the guest executes its syscall instruction."""
        uc, arch = self.uc, self.arch
        nr = uc.reg_read(arch.nr_reg)
        args = [uc.reg_read(r) for r in arch.arg_regs]
        if arch.stack_arg_offset is not None:  # e.g. MIPS o32: args 5 and 6 are on the stack
            sp = uc.reg_read(arch.sp_reg)
            for i in range(6 - len(args)):
                try:
                    args.append(self.u32(sp + arch.stack_arg_offset + 4 * i))
                except Fault:
                    args.append(0)
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
        self._set_result(ret)

    def _set_result(self, ret: int) -> None:
        """Deliver a syscall result in the arch's convention. Handlers return a value or
        -errno using i386 errno numbers; other ABIs get their own numbers and error flag."""
        arch, uc = self.arch, self.uc
        mask = (1 << (arch.word_size * 8)) - 1
        if ret < 0:
            errno = arch.errno_map.get(-ret, -ret)
            if arch.error_flag_reg is not None:   # MIPS: $a3 = 1, $v0 = positive errno
                uc.reg_write(arch.error_flag_reg, 1)
                uc.reg_write(arch.ret_reg, errno)
            else:                                  # i386: -errno in the result register
                uc.reg_write(arch.ret_reg, -errno & mask)
            return
        if arch.error_flag_reg is not None:
            uc.reg_write(arch.error_flag_reg, 0)
        uc.reg_write(arch.ret_reg, ret & mask)

    def current_pc(self) -> int:
        """Address to resume at. On ARM the low bit selects Thumb, taken from CPSR.T."""
        pc = self.uc.reg_read(self.arch.pc_reg)
        if self.arch.cpsr_reg is not None and self.uc.reg_read(self.arch.cpsr_reg) & 0x20:
            pc |= 1
        return pc

    def _save_ctx(self):
        """Snapshot the CPU from inside a syscall hook so that resuming continues AFTER the syscall.
        On x86-64 the hook runs with RIP still at the `syscall` instruction; without this fix a
        restored context would execute the syscall a second time."""
        ctx = self.uc.context_save()
        if self.arch.syscall_insn_len:
            ctx.reg_write(self.arch.pc_reg,
                          self.uc.reg_read(self.arch.pc_reg) + self.arch.syscall_insn_len)
        return ctx

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
                "mapped_bytes": self.mapped_bytes, "cwd": self.cwd,
                "reserved": [list(r) for r in self.reserved]}

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
        self.reserved = [list(r) for r in snap["reserved"]]
        self.uc.context_restore(record["ctx"])
        self._set_result(record["pid"])
        self.path_syscalls = 0
        return self.current_pc()

    @property
    def has_pending_forks(self) -> bool:
        return bool(self._forks)

    def abandon_path(self, why: str) -> None:
        """Give up on the current forked path (it isn't finishing) and go back to its parent."""
        self.log("process", "fork", note=f"forked path abandoned: {why}",
                 syscalls_on_path=self.path_syscalls)
        self._end_process("path_abandoned")

    # ---------------------------------------------------------------- threads
    def _wake_due(self) -> None:
        for t in self.threads:
            if t.state in ("futex", "sleep", "epoll") and t.wake_at is not None and t.wake_at <= self.vtime + 1e-12:
                t.pending_ret = -ETIMEDOUT if t.state == "futex" else 0
                t.state, t.wait_addr, t.wake_at = "ready", None, None

    def _pick_next(self) -> Optional[Thread]:
        self._wake_due()
        n, i = len(self.threads), self.threads.index(self.cur)
        for step in range(1, n + 1):              # round-robin, the current thread last
            t = self.threads[(i + step) % n]
            if t.state == "ready":
                return t
        timed = [t for t in self.threads if t.state in ("futex", "sleep", "epoll") and t.wake_at is not None]
        if not timed:
            return None
        self.vtime = max(self.vtime, min(t.wake_at for t in timed))   # nothing can run: time passes
        self._wake_due()
        return self._pick_next()

    def _request_switch(self) -> None:
        nxt = self._pick_next()
        if nxt is None:                           # every thread is blocked with nothing to wake it
            self._stop("deadlock")
            return
        self.switch_to = nxt
        self.uc.emu_stop()

    def _block(self, state: str, addr: Optional[int] = None, until: Optional[float] = None) -> int:
        cur = self.cur
        cur.state, cur.wait_addr, cur.wake_at = state, addr, until
        self._block_seq += 1
        cur.seq = self._block_seq
        self._request_switch()
        return 0

    def _wake_epoll_waiters(self) -> None:
        """Something became readable: threads blocked in epoll_wait re-run it to collect events."""
        for t in self.threads:
            if t.state == "epoll":
                t.state, t.wake_at, t.restart = "ready", None, True

    def yield_thread(self) -> None:
        """Give another runnable thread the CPU (time-slice expiry or sched_yield)."""
        self.cur.state = "ready"
        self._request_switch()

    def _futex_wake(self, addr: int, count: int) -> int:
        waiters = sorted((t for t in self.threads if t.state == "futex" and t.wait_addr == addr),
                         key=lambda t: t.seq)[:count]
        for t in waiters:
            t.state, t.wait_addr, t.wake_at, t.pending_ret = "ready", None, None, None
        return len(waiters)

    def activate_thread(self) -> int:
        """Called by the run loop after emu_stop(): swap CPU state to the requested thread."""
        nxt, self.switch_to = self.switch_to, None
        old = self.cur
        if old.state != "dead":
            old.ctx = self.uc.context_save()
        if nxt.ctx is not None:
            self.uc.context_restore(nxt.ctx)
        if nxt.setup is not None:                 # first run: clone() returns 0 in the child
            self.uc.reg_write(self.arch.ret_reg, 0)
            if nxt.setup["sp"]:
                self.uc.reg_write(self.arch.sp_reg, nxt.setup["sp"])
            if nxt.setup["tls"] is not None and self.arch.set_tls is not None:
                self.arch.set_tls(self.uc, nxt.setup["tls"])
            nxt.setup = None
        elif nxt.restart and self.arch.syscall_insn_len:      # re-run the epoll_wait it was blocked in
            self.uc.reg_write(self.arch.nr_reg, nxt.restart_nr)
            self.uc.reg_write(self.arch.pc_reg,
                              self.uc.reg_read(self.arch.pc_reg) - self.arch.syscall_insn_len)
        elif nxt.pending_ret is not None:
            self._set_result(nxt.pending_ret)
        nxt.restart = False
        nxt.pending_ret, nxt.state, nxt.wait_addr, nxt.wake_at = None, "ready", None, None
        if old.state == "dead":
            self.threads.remove(old)
        self.cur = nxt
        return self.current_pc()

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
        if len(self.threads) > 1 and self.cur is not self.threads[0]:    # a worker thread ends
            th = self.cur
            th.state = "dead"
            if th.clear_tid:
                try:
                    self.put32(th.clear_tid, 0)
                except Fault:
                    pass
                self._futex_wake(th.clear_tid, 1)
            self._request_switch()
            return 0
        return self.sys_exit_group(code)

    def sys_exit_group(self, code, *_):
        self.log("process", "exit", code=s32(code))
        self._end_process(f"exit({s32(code)})")
        return 0

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
        self._forks.append({"ctx": self._save_ctx(), "pid": pid, "snap": self._snapshot()})
        self.log("process", "fork", child_pid=pid)
        return 0

    sys_vfork = sys_fork

    def sys_clone(self, flags, stack=0, ptid=0, a3=0, a4=0, *_):
        if flags & CLONE_VM:
            if flags & CLONE_THREAD and self.arch.clone_tls_arg is not None:
                if len(self.threads) >= MAX_THREADS:
                    return -EAGAIN
                tid = self._next_pid
                self._next_pid += 1
                tls, ctid = (a4, a3) if self.arch.clone_tls_arg == 4 else (a3, a4)
                th = Thread(tid=tid, ctx=self._save_ctx(), state="ready",
                            setup={"sp": stack, "tls": tls if flags & CLONE_SETTLS else None})
                if flags & CLONE_CHILD_CLEARTID:
                    th.clear_tid = ctid
                if flags & CLONE_PARENT_SETTID and ptid:
                    self.put32(ptid, tid)
                if flags & CLONE_CHILD_SETTID and ctid:
                    self.put32(ctid, tid)
                self.threads.append(th)
                self.threads_created += 1
                if len(self.threads) == 2:            # first extra thread: the running slice was planned
                    self.replan = True                # for one thread, so stop and re-plan with time slicing
                    self.uc.emu_stop()
                if self.threads_created <= 8:
                    self.log("process", "clone", note="thread created (cooperative scheduling)", tid=tid)
                return tid
            tid = self._next_pid
            self._next_pid += 1
            self.log("process", "clone", note="thread creation not emulated", flags=hex(flags))
            return tid
        return self.sys_fork()

    def sys_execve(self, path, argv, envp, *_):
        p = self.cstr(path)
        args = []
        for i in range(64):
            ptr = self.uptr(argv + self.arch.word_size * i) if argv else 0
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
        return self.cur.tid

    def sys_getppid(self, *_):
        return self.ppid

    def sys_getuid(self, *_):
        return 0

    sys_getuid32 = sys_getgid32 = sys_geteuid32 = sys_getegid32 = sys_getuid
    sys_getgid = sys_geteuid = sys_getegid = sys_getuid

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

    def sys_set_tid_address(self, addr=0, *_):
        self.cur.clear_tid = addr
        return self.cur.tid

    def sys_set_robust_list(self, *_):
        return 0

    def sys_futex(self, uaddr, op, val, timeout=0, uaddr2=0, val3=0, *_):
        cmd = op & 0x7F
        if cmd in (0, 9):                                     # FUTEX_WAIT / FUTEX_WAIT_BITSET
            if self.u32(uaddr) != val & 0xFFFFFFFF:
                return -EAGAIN
            delay = None
            if timeout:
                delay = self._read_timespec(timeout)
                if cmd == 9:                                  # WAIT_BITSET takes an absolute deadline
                    delay = max(0.0, delay - self.now())
            if len(self.threads) == 1:                        # nothing can ever wake us
                if delay is None:
                    return 0                                  # spurious wake-up keeps the program moving
                self.vtime += delay
                return -ETIMEDOUT
            return self._block("futex", addr=uaddr, until=None if delay is None else self.vtime + delay)
        if cmd in (1, 10):                                    # FUTEX_WAKE / FUTEX_WAKE_BITSET
            return self._futex_wake(uaddr, val & 0xFFFFFFFF)
        return -ENOSYS

    def sys_tgkill(self, *_):
        return 0                                              # runtimes signal their own threads (preemption)

    sys_tkill = sys_tgkill

    def sys_times(self, buf, *_):
        if buf:
            self.write(buf, b"\0" * (4 * self.arch.word_size))     # struct tms: four clock_t
        return int(self.vtime * 100) & 0x7FFFFFFF

    def sys_inotify_init(self, *_):
        return self._alloc_fd(Device("special"))

    def sys_epoll_create1(self, *_):
        return self._alloc_fd(Epoll())

    sys_epoll_create = sys_epoll_create1

    def sys_eventfd2(self, initval, flags=0, *_):
        return self._alloc_fd(EventFd(initval))

    sys_eventfd = sys_eventfd2

    def sys_epoll_ctl(self, epfd, op, fd, event, *_):
        ep = self.fds.get(s32(epfd))
        if not isinstance(ep, Epoll):
            return -EBADF
        fd = s32(fd)
        if op == EPOLL_CTL_DEL:
            ep.watch.pop(fd, None)
            ep.reported.discard(fd)
            return 0
        if fd not in self.fds:
            return -EBADF
        if (op == EPOLL_CTL_ADD) == (fd in ep.watch):
            return -EEXIST if op == EPOLL_CTL_ADD else -ENOENT
        layout = self._bo + ("IQ" if self.arch.epoll_event_packed else "IxxxxQ")
        events, data = struct.unpack(layout, self.read(event, struct.calcsize(layout)))
        ep.watch[fd] = [events, data]
        ep.reported.discard(fd)
        return 0

    def _epoll_events(self, ep: Epoll, maxevents: int) -> list:
        out = []
        for fd, (events, data) in list(ep.watch.items()):
            obj = self.fds.get(fd)
            if obj is None:
                continue
            mask = 0
            if events & EPOLLIN and self._readable(fd):
                mask |= EPOLLIN
            if events & EPOLLOUT and isinstance(obj, (Sock, Pipe, OpenFile)):
                mask |= EPOLLOUT
            if not mask:
                ep.reported.discard(fd)
                continue
            if events & EPOLLET:                 # edge-triggered: report a state change once
                if fd in ep.reported:
                    continue
                ep.reported.add(fd)
            out.append((mask, data))
            if len(out) >= maxevents:
                break
        return out

    def sys_epoll_wait(self, epfd, events, maxevents, timeout, *_):
        ep = self.fds.get(s32(epfd))
        if not isinstance(ep, Epoll):
            return -EBADF
        maxevents = s32(maxevents)
        if maxevents <= 0:
            return -EINVAL
        ready = self._epoll_events(ep, maxevents)
        if ready:
            layout = self._bo + ("IQ" if self.arch.epoll_event_packed else "IxxxxQ")
            self.write(events, b"".join(struct.pack(layout, m, d) for m, d in ready))
            return len(ready)
        wait_ms = s32(timeout)
        if wait_ms == 0:
            return 0
        if len(self.threads) == 1:               # nothing else could ever make it ready
            if wait_ms > 0:
                self.vtime += wait_ms / 1000
            return 0
        self.cur.restart_nr = self.uc.reg_read(self.arch.nr_reg)
        return self._block("epoll", until=None if wait_ms < 0 else self.vtime + wait_ms / 1000)

    sys_epoll_pwait = sys_epoll_wait

    def sys_inotify_add_watch(self, *_):
        return 1

    def sys_inotify_rm_watch(self, *_):
        return 0

    def sys_sched_yield(self, *_):
        if len(self.threads) > 1:
            self.yield_thread()
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
            self.put_uptr(tptr, t)
        return t

    def sys_gettimeofday(self, tv, *_):
        if tv:
            sec = self.now()
            self.write(tv, self.pack_words(int(sec), int((sec % 1) * 1_000_000)))
        return 0

    def sys_clock_gettime(self, clk, ts, *_):
        if ts:
            sec = self.now()
            self.write(ts, self.pack_words(int(sec), int((sec % 1) * 1e9)))
        return 0

    def sys_nanosleep(self, req, *_):
        return self._sleep(self._read_timespec(req) if req else 0.0)

    def sys_clock_gettime64(self, clk, ts, *_):
        if ts:                                            # 32-bit ABIs, 64-bit time_t
            sec = self.now()
            self.write(ts, struct.pack(self._bo + "qq", int(sec), int((sec % 1) * 1e9)))
        return 0

    def sys_clock_nanosleep_time64(self, clock, flags, req, *_):
        if not req:
            return 0
        sec, nsec = struct.unpack(self._bo + "qq", self.read(req, 16))
        return self._sleep(sec + nsec / 1e9)

    def _sleep(self, delay: float) -> int:
        if len(self.threads) > 1:
            return self._block("sleep", until=self.vtime + delay)   # others run while this one sleeps
        self.vtime += delay
        return 0

    def sys_clock_nanosleep(self, clock, flags, req, *_):
        return self.sys_nanosleep(req)

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
        anonymous = bool(flags & self.arch.map_anonymous) or s32(fd) == -1
        if flags & MAP_FIXED and addr % PAGE == 0:
            base = addr
            self._unmap_range(base, size)                    # MAP_FIXED replaces what was there
        elif addr and addr % PAGE == 0 and addr + size < self.stack_low and self._blocker(addr, size) is None:
            base = addr                                      # honour a free hint, as Linux does
        else:
            base = self._pick_address(size)
            if base is None:
                return -ENOMEM
        if prot == 0 and anonymous:                          # PROT_NONE: reserve address space only
            self._reserve(base, size)
            return base
        if not self._map(base, size):
            return -ENOMEM
        if not anonymous:
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

    def sys_mmap(self, a0, a1, a2, a3, a4, a5):
        if self.arch.old_mmap_struct:
            # old i386 mmap(): a single pointer to an argument block
            return self._sys_mmap(*struct.unpack(self._bo + "6I", self.read(a0, 24)))
        return self._sys_mmap(a0, a1, a2, a3, a4, a5)      # other ABIs: ordinary arguments

    def sys_munmap(self, addr, length, *_):
        self._unmap_range(addr & ~(PAGE - 1), _align_up(length))
        return 0

    def sys_mprotect(self, addr, length, prot, *_):
        # Mapped memory is already RWX. Making a *reserved* range accessible commits it.
        if prot != 0 and length and not self._commit_reserved(addr & ~(PAGE - 1), _align_up(length)):
            return -ENOMEM
        return 0

    # ---------------------------------------------------------------- misc info
    def _random(self, n: int) -> bytes:
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    def sys_getrandom(self, buf, n, *_):
        self.write(buf, self._random(n))
        return n

    def sys_uname(self, buf, *_):
        fields = [b"Linux", b"localhost", b"3.2.0", b"#1 SMP", self.arch.uname_machine.encode(), b"(none)"]
        self.write(buf, b"".join(f.ljust(65, b"\0") for f in fields))
        return 0

    def sys_sysinfo(self, buf, *_):
        w = self.arch.word_size
        raw = bytearray(13 * w + 12 if w == 8 else 64)     # 112 bytes on 64-bit, 64 on 32-bit
        raw[0:w] = self.pack_words(86400)                   # uptime
        raw[4 * w:5 * w] = self.pack_words(512 * 1024 * 1024)   # totalram
        raw[5 * w:6 * w] = self.pack_words(256 * 1024 * 1024)   # freeram
        struct.pack_into(self._bo + "H", raw, 10 * w, 1)              # procs
        struct.pack_into(self._bo + "I", raw, 13 * w, 1)              # mem_unit
        self.write(buf, bytes(raw))
        return 0

    def sys_getrlimit(self, res, buf, *_):
        self.write(buf, self.pack_words(0x7FFFFFFF, 0x7FFFFFFF))
        return 0

    def sys_prlimit64(self, pid, resource, new, old, *_):
        if old:  # struct rlimit64 is two u64 on every ABI; the stack limit is a realistic 8 MiB
            soft = 8 * 1024 * 1024 if resource == 3 else 0xFFFFFFFFFFFFFFFF
            self.write(old, struct.pack(self._bo + "QQ", soft, 0xFFFFFFFFFFFFFFFF))
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

    def sys_fcntl(self, fd, cmd, arg=0, *_):
        obj = self.fds.get(s32(fd))
        if obj is None:
            return -EBADF
        if cmd in (0, 1030):            # F_DUPFD / F_DUPFD_CLOEXEC: lowest free fd >= arg
            new = max(3, s32(arg))
            while new in self.fds:
                new += 1
            self.fds[new] = obj
            return new
        if cmd == 3:                    # F_GETFL: sockets and pipes are read/write
            return 2 if isinstance(obj, (Sock, Pipe)) else 0
        return 0                        # F_GETFD/F_SETFD/F_SETFL: accepted, no effect

    sys_fcntl64 = sys_fcntl

    def sys_arm_set_tls(self, addr, *_):
        if self.arch.set_tls is not None:
            self.arch.set_tls(self.uc, addr)
        return 0

    def sys_arm_cacheflush(self, *_):
        return 0

    def sys_arch_prctl(self, code, addr, *_):
        """x86-64 TLS: ARCH_SET_FS installs the thread pointer in the FS base register."""
        ARCH_SET_FS, ARCH_GET_FS = 0x1002, 0x1003
        if code == ARCH_SET_FS and self.arch.set_tls is not None:
            self.arch.set_tls(self.uc, addr)
            return 0
        if code == ARCH_GET_FS:
            from unicorn.x86_const import UC_X86_REG_FS_BASE
            self.put_uptr(addr, self.uc.reg_read(UC_X86_REG_FS_BASE))
            return 0
        return -EINVAL

    def sys_sigaltstack(self, *_):
        return 0

    def sys_madvise(self, *_):
        return 0

    def sys_sched_getaffinity(self, pid, length, mask, *_):
        if length < 8:
            return -EINVAL
        self.write(mask, struct.pack(self._bo + "Q", 1))      # one CPU, so runtimes size themselves sensibly
        return 8

    def sys_newfstatat(self, dirfd, path, buf, flags, *_):
        """fstatat(): relative to dirfd is not modelled; an empty path with AT_EMPTY_PATH is fstat()."""
        if flags & 0x1000 and self.cstr(path) == "":
            return self._fstat(dirfd, buf, False)
        return self._stat_path(path, buf, False)

    def sys_set_thread_area(self, addr, *_):
        if self.arch.set_tls is None:
            return -ENOSYS  # x86 needs a GDT/segment setup we don't emulate; a real sample would fault
        self.arch.set_tls(self.uc, addr)
        return 0

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
        writing = flags & (O_WRONLY | O_RDWR) or flags & self.arch.o_creat
        if path in self.files or writing:
            if path not in self.files:
                if len(self.files) >= MAX_FILES:
                    return -ENOMEM
                self.files[path] = bytearray()
                self.log("file", "open", path=path, note="created", flags=oct(flags))
            elif flags & self.arch.o_trunc:
                self.files[path] = bytearray()
            content = self.files[path]
            return self._alloc_fd(OpenFile(path, flags, content, len(content) if flags & self.arch.o_append else 0))
        if path not in self._missing_seen and len(self._missing_seen) < 200:
            self._missing_seen.add(path)
            self.log("file", "open", path=path, note="probed, does not exist")
        return -ENOENT

    def sys_open(self, path, flags, mode, *_):
        return self._open(self.cstr(path), flags)

    def sys_openat(self, dirfd, path, flags, *_):
        return self._open(self.cstr(path), flags)

    def sys_creat(self, path, mode, *_):
        return self._open(self.cstr(path), self.arch.o_creat | O_WRONLY | self.arch.o_trunc)

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
            if obj.live is not None and not obj.recv_queue:
                data = self._live_recv(obj, n)
                if data is None:
                    return -EAGAIN
            elif obj.recv_queue:
                data = self._pop_queue(obj, n)
            else:
                return 0 if obj.type == SOCK_STREAM else -EAGAIN
        elif isinstance(obj, EventFd):
            if obj.counter == 0:
                return -EAGAIN
            data = struct.pack(self._bo + "Q", obj.counter)
            obj.counter = 0
        elif isinstance(obj, Pipe):
            data = bytes(obj.buf[:n])
            del obj.buf[:n]
        else:
            return -EBADF
        self.write(buf, data)
        return len(data)

    def _live_recv(self, sock: Sock, n: int) -> Optional[bytes]:
        """Receive from the real network, really waiting (bounded) like a blocking recv would."""
        data = sock.live.recv(n)
        if data is None:
            self.vtime += self.live_net.wait_any([sock.live], LIVE_MAX_WAIT)
            data = sock.live.recv(n)
        if data:  # keep what the remote end sent: commands, downloaded payloads
            if len(self.received) < MAX_RECEIVED_ENTRIES and self._received_bytes < MAX_RECEIVED_BYTES:
                self._received_bytes += len(data)
                remote = sock.remote or {}
                ip, port = remote.get("ip"), remote.get("port")
                if sock.live_peer:
                    ip, port = sock.live_peer
                self.received.append({"ip": ip, "port": port, "data": data})
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
            self._wake_epoll_waiters()
            return len(data)
        if isinstance(obj, EventFd):
            if len(data) < 8:
                return -EINVAL
            obj.counter += struct.unpack(self._bo + "Q", data[:8])[0]
            self._wake_epoll_waiters()
            return 8
        return -EBADF

    def sys_writev(self, fd, iov, iovcnt, *_):
        obj = self.fds.get(s32(fd))
        if obj is None:
            return -EBADF
        total = 0
        for i in range(min(iovcnt, 64)):
            base, length = self._iovec(iov, i)
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
            self.write(result, struct.pack(self._bo + "Q", r))
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
        mode_off, mode_bytes, size_off, total = self.arch.stat64 if is64 else self.arch.stat32
        raw = bytearray(total)
        struct.pack_into(self._bo + ("I" if mode_bytes == 4 else "H"), raw, mode_off,
                         mode if mode_bytes == 4 else mode & 0xFFFF)
        struct.pack_into(self._bo + ("Q" if is64 else "I"), raw, size_off, size)
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

    def sys_pipe2(self, ptr, flags, *_):
        return self.sys_pipe(ptr)

    def sys_pipe(self, ptr, *_):
        pipe = Pipe(bytearray())
        first, second = self._alloc_fd(pipe), self._alloc_fd(pipe)
        if self.arch.pipe_second_reg is not None:   # MIPS: fds come back in $v0/$v1, no pointer
            self.uc.reg_write(self.arch.pipe_second_reg, second)
            return first
        self.write(ptr, struct.pack(self._bo + "II", first, second))
        return 0

    # ---------------------------------------------------------------- sockets
    def sys_socketcall(self, call, argp, *_):
        name = _SOCKETCALLS.get(call)
        if name is None:
            return -EINVAL
        n = 6 if name in ("sendto", "recvfrom") else 3
        args = list(struct.unpack(f"{self._bo}{n}I", self.read(argp, 4 * n))) if argp else [0] * n
        args += [0] * (6 - len(args))
        self.counts[f"socketcall:{name}"] += 1
        handler = getattr(self, f"sys_{name}", None)
        return handler(*args) if handler else -ENOSYS

    def _parse_sockaddr(self, addr: int, alen: int) -> Optional[dict]:
        if not addr or alen < 2:
            return None
        raw = self.read(addr, min(alen, 128))
        family = struct.unpack_from(self._bo + "H", raw)[0]
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
        typ = self.arch.sock_type_map.get(typ, typ)  # other ABIs number SOCK_STREAM/DGRAM differently
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
            sock.peer = (remote["ip"], remote["port"])
            proto = "udp" if sock.type == SOCK_DGRAM else "tcp"
            self.network.append({"op": "connect", "proto": proto, **remote})
            if (proto == "tcp" and self.live_net is not None
                    and self.live_net.allows(remote["ip"], remote["port"])):
                session = self.live_net.open(remote["ip"], remote["port"])
                if session is None:
                    self.log("network", "connect", proto=proto, live=False,
                             note="real connection failed or refused", **remote)
                    return -ECONNREFUSED
                sock.live = session
                self.log("network", "connect", proto=proto, live=True, **remote)
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
            self.write(addr, struct.pack(self._bo + "HH", AF_INET, 0) + b"\0" * 12)
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
        if remote.get("ip"):
            sock.peer = (remote["ip"], remote["port"])
        self._record_sent(sock, proto, remote, data)
        if sock.live is not None and proto == "tcp":
            return len(data) if sock.live.send(data) >= 0 else -EPIPE
        if (proto == "udp" and self.live_net is not None and remote.get("ip")
                and self.live_net.allows(remote["ip"], remote["port"])):
            if sock.live is None:
                sock.live = self.live_net.udp()
            sock.live_peer = (remote["ip"], remote["port"])
            return len(data) if sock.live.send(data, remote["ip"], remote["port"]) >= 0 else -EPIPE
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
        if self.arch.word_size == 8:     # struct msghdr: name*, namelen (+pad), iov*, iovlen
            name, namelen = self.uptr(msg), struct.unpack(self._bo + "I", self.read(msg + 8, 4))[0]
            iov, iovlen = self.uptr(msg + 16), self.uptr(msg + 24)
        else:
            name, namelen, iov, iovlen = struct.unpack(self._bo + "IIII", self.read(msg, 16))
        data = b""
        for i in range(min(iovlen, 64)):
            base, length = self._iovec(iov, i)
            data += self.read(base, min(length, 1 << 20))
        return self._send(sock, data, self._parse_sockaddr(name, namelen) if name else None)

    def sys_recvfrom(self, fd, buf, n, flags, addr, alenp):
        sock = self.fds.get(s32(fd))
        if not isinstance(sock, Sock):
            return -EBADF
        got = self.sys_read(fd, buf, n)
        if got >= 0 and addr and alenp and sock.peer:
            # Resolvers such as musl's discard replies whose source address isn't the server
            # they queried, so the sender must be reported.
            ip, port = sock.peer
            sa = (struct.pack(self._bo + "H", AF_INET) + struct.pack(">H", port)
                  + bytes(int(o) for o in ip.split(".")) + b"\0" * 8)
            room = self.u32(alenp)
            self.write(addr, sa[:room] if room else sa)
            self.put32(alenp, len(sa))
        return got

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
            return bool(obj.recv_queue) or (obj.live is not None and obj.live.readable())
        if isinstance(obj, Pipe):
            return bool(obj.buf)
        if isinstance(obj, EventFd):
            return obj.counter > 0
        return isinstance(obj, OpenFile) or (isinstance(obj, Device) and obj.name == "urandom")

    def _live_idle_wait(self, read_fds, timeout_s: float) -> None:
        """If a real connection is being watched and nothing is readable yet, really wait for it
        (bounded) so a reply from the remote end isn't missed by racing ahead in virtual time."""
        live = [self.fds[fd].live for fd in read_fds
                if isinstance(self.fds.get(fd), Sock) and self.fds[fd].live is not None
                and not self.fds[fd].live.closed]
        if live and not any(self._readable(fd) for fd in read_fds):
            self.vtime += self.live_net.wait_any(live, min(timeout_s, LIVE_MAX_WAIT))

    def sys_poll(self, fds, nfds, timeout, *_):
        if self.live_net is not None and s32(timeout) > 0:
            watch = []
            for i in range(min(nfds, 1024)):
                fd, events, _r = struct.unpack(self._bo + "ihh", self.read(fds + 8 * i, 8))
                if fd >= 0 and events & POLLIN:
                    watch.append(fd)
            self._live_idle_wait(watch, s32(timeout) / 1000)
        ready = 0
        for i in range(min(nfds, 1024)):
            fd, events, _rev = struct.unpack(self._bo + "ihh", self.read(fds + 8 * i, 8))
            rev = 0
            if fd >= 0 and fd in self.fds:
                if events & POLLIN and self._readable(fd):
                    rev |= POLLIN
                if events & POLLOUT:
                    rev |= POLLOUT
            self.write(fds + 8 * i + 6, struct.pack(self._bo + "h", rev))
            ready += 1 if rev else 0
        if not ready and s32(timeout) > 0:
            self.vtime += s32(timeout) / 1000
        return ready

    def _select(self, n: int, rfds: int, wfds: int, efds: int, timeout_s: Optional[float]) -> int:
        """select(2) core. fd_set is an array of `unsigned long`, so its word width follows the ABI."""
        n = min(n, 1024)
        bits = self.arch.word_size * 8
        nwords = (n + bits - 1) // bits
        if self.live_net is not None and timeout_s is not None and rfds:
            words = self.read_words(rfds, nwords)
            watch = [fd for fd in range(n) if words[fd // bits] >> (fd % bits) & 1]
            self._live_idle_wait(watch, timeout_s)
        ready = 0
        for ptr, kind in ((rfds, "r"), (wfds, "w"), (efds, "e")):
            if not ptr:
                continue
            words = list(self.read_words(ptr, nwords))
            for fd in range(n):
                if not words[fd // bits] >> (fd % bits) & 1:
                    continue
                keep = (kind == "w" and fd in self.fds) or (kind == "r" and self._readable(fd))
                if keep:
                    ready += 1
                else:
                    words[fd // bits] &= ~(1 << (fd % bits))
            self.write(ptr, self.pack_words(*words))
        if not ready and timeout_s is not None:
            self.vtime += timeout_s
        return ready

    def sys__newselect(self, n, rfds, wfds, efds, timeout, *_):
        return self._select(n, rfds, wfds, efds, self._read_timeval(timeout) if timeout else None)

    def sys_select(self, a0, a1=0, a2=0, a3=0, a4=0, *_):
        if self.arch.select_takes_struct:   # old i386: one pointer to the five arguments
            a0, a1, a2, a3, a4 = self.read_words(a0, 5)
        return self.sys__newselect(a0, a1, a2, a3, a4)

    def sys_pselect6(self, n, rfds, wfds, efds, timeout, *_):
        return self._select(n, rfds, wfds, efds, self._read_timespec(timeout) if timeout else None)


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
