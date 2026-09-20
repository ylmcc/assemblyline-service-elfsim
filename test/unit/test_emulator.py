import struct

import pytest

from elfsim_service.emulator import UnsupportedElf, emulate
from test.unit.elfbuilder import Prog

C2_IP, C2_PORT = "198.51.100.7", 4444  # RFC 5737 documentation range


def _run(prog: Prog, **kw):
    return emulate(prog.build(), timeout_s=10, **kw)


def test_exit_code_is_reported():
    p = Prog()
    p.exit(7)
    r = _run(p)
    assert r.stop_reason == "exit(7)"
    assert r.error is None


def test_stdout_is_captured():
    p = Prog()
    msg = p.d(b"hello")
    p.sys(4, 1, msg, 5)
    p.exit(0)
    assert _run(p).stdout == b"hello"


def test_direct_socket_and_connect_are_recorded():
    p = Prog()
    addr = p.d(Prog.sockaddr_in(C2_IP, C2_PORT))
    p.sys(359, 2, 1, 0)          # socket(AF_INET, SOCK_STREAM, 0)
    p.ebx_from_eax()
    p.mov(1, addr)
    p.mov(2, 16)
    p.mov(0, 362)                # connect(fd, addr, 16)
    p.raw(b"\xcd\x80")
    p.exit(0)
    r = _run(p)
    assert {"op": "connect", "proto": "tcp", "family": "inet", "ip": C2_IP, "port": C2_PORT} in r.network


def test_socketcall_multiplexer_is_decoded():
    p = Prog()
    addr = p.d(Prog.sockaddr_in(C2_IP, C2_PORT))
    sock_args = p.ptrs(2, 1, 0)
    conn_args = p.ptrs(0, addr, 16)   # slot 0 patched with the fd below
    p.sys(102, 1, sock_args)          # socketcall(SYS_SOCKET)
    p.store_eax(conn_args)
    p.sys(102, 3, conn_args)          # socketcall(SYS_CONNECT)
    p.exit(0)
    r = _run(p)
    assert [n["ip"] for n in r.network if n["op"] == "connect"] == [C2_IP]


def test_dns_query_is_parsed_and_answered_with_sinkhole():
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    p = Prog()
    dest = p.d(Prog.sockaddr_in("203.0.113.53", 53))
    q = p.d(query)
    buf = p.d(b"\0" * 128)
    p.sys(359, 2, 2, 0)                         # socket(AF_INET, SOCK_DGRAM)
    p.ebx_from_eax()
    p.mov(1, q); p.mov(2, len(query)); p.mov(6, 0); p.mov(7, dest); p.mov(5, 16)
    p.mov(0, 369)                               # sendto
    p.raw(b"\xcd\x80")
    p.mov(1, buf); p.mov(2, 128); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0)
    p.mov(0, 371)                               # recvfrom -> eax = length
    p.raw(b"\xcd\x80")
    p.edx_from_eax()
    p.sys(4, 1, buf)                            # write(1, buf, edx) ... edx clobbered below?
    p.exit(0)
    # sys() reloads edx only if given; here edx keeps the recvfrom length
    r = _run(p)
    assert any(n["op"] == "dns_query" and n["domain"] == "c2.test" for n in r.network)
    assert bytes([192, 0, 2, 53]) in r.stdout


def test_file_write_and_chmod_are_captured_in_memory():
    p = Prog()
    path = p.cstr("/tmp/dropped")
    body = p.d(b"payload")
    p.sys(5, path, 0o101)        # open(O_WRONLY|O_CREAT)
    p.ebx_from_eax()
    p.mov(1, body); p.mov(2, 7); p.mov(0, 4)
    p.raw(b"\xcd\x80")           # write(fd, body, 7)
    p.sys(15, path, 0o755)       # chmod
    p.exit(0)
    r = _run(p)
    assert r.files == {"/tmp/dropped": b"payload"}
    assert r.file_modes == {"/tmp/dropped": 0o755}


def test_fork_runs_child_then_rewinds_to_parent():
    p = Prog()
    sh, dashc, cmd = p.cstr("/bin/sh"), p.cstr("-c"), p.cstr("echo hi")
    argv = p.ptrs(sh, dashc, cmd, 0)
    parent_msg = p.d(b"P")
    p.sys(2)                     # fork
    p.jnz("parent")
    p.sys(11, sh, argv, 0)       # child: execve("/bin/sh", ["/bin/sh","-c","echo hi"])
    p.exit(1)                    # unreachable if execve ended the child
    p.label("parent")
    p.sys(4, 1, parent_msg, 1)
    p.exit(0)
    r = _run(p)
    kinds = [(e["syscall"]) for e in r.events]
    assert "fork" in kinds and "execve" in kinds
    execve = next(e for e in r.events if e["syscall"] == "execve")
    assert execve["path"] == "/bin/sh" and execve["argv"] == ["/bin/sh", "-c", "echo hi"]
    assert r.stdout == b"P"
    assert r.stop_reason == "exit(0)"


def test_unmapped_access_is_a_fault_with_pc():
    p = Prog()
    p.raw(b"\xa1" + struct.pack("<I", 0xDEADBEEF))   # mov eax, [0xdeadbeef]
    r = _run(p)
    assert r.stop_reason == "fault"
    assert "unmapped" in r.error["type"]
    assert r.error["pc"] == hex(0x08048100)


def test_instruction_limit_stops_an_infinite_loop():
    p = Prog()
    p.raw(b"\xeb\xfe")           # jmp $
    r = emulate(p.build(), max_instructions=10_000, timeout_s=10)
    assert r.stop_reason == "instruction_limit"


def test_unknown_syscall_gets_enosys_and_is_reported_once():
    p = Prog()
    p.sys(9999)
    p.sys(9999)
    p.exit(0)
    r = _run(p)
    assert r.unknown_syscalls == {"sys_9999": 2}
    assert sum(1 for e in r.events if e["syscall"] == "sys_9999") == 1


@pytest.mark.parametrize("blob", [b"not an elf", b"\x7fELF" + b"\0" * 10])
def test_malformed_input_is_unsupported(blob):
    with pytest.raises(UnsupportedElf):
        emulate(blob)


def test_other_architectures_are_unsupported_for_now():
    p = Prog()
    p.exit(0)
    with pytest.raises(UnsupportedElf, match="unsupported machine"):
        emulate(p.build(machine=40))   # EM_ARM


def test_fork_child_memory_writes_do_not_leak_into_the_parent_path():
    p = Prog()
    slot = p.d(b"A")
    p.sys(2)                     # fork
    p.jnz("parent")
    p.poke_byte(slot, ord("B"))  # child scribbles over shared-looking memory ...
    p.exit(0)                    # ... then exits, rewinding to the parent
    p.label("parent")
    p.sys(4, 1, slot, 1)         # parent must still see its own copy
    p.exit(0)
    assert _run(p).stdout == b"A"


def test_a_child_that_never_finishes_is_abandoned_and_the_parent_still_runs():
    p = Prog()
    msg = p.d(b"P")
    p.sys(2)                     # fork
    p.jnz("parent")
    p.label("spin")
    p.sys(158)                   # child: sched_yield forever (an idle daemon loop)
    p.jmp("spin")
    p.label("parent")
    p.sys(4, 1, msg, 1)
    p.exit(0)
    r = emulate(p.build(), timeout_s=10)
    assert r.stdout == b"P"
    assert any("abandoned" in e.get("note", "") for e in r.events)
