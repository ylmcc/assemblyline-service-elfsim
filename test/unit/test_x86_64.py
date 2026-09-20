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
