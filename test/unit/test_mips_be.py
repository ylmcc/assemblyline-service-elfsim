"""Big-endian MIPS: same ABI as little-endian, other byte order. These target what byte order
touches: guest structs, pointers on the stack and in argv arrays, and the error convention."""
import struct

from elfsim_service.emulator import emulate
from test.unit.mipsbuilder import A3, V0, MipsBEProg

C2_IP, C2_PORT = "198.51.100.7", 4444


def _run(prog, **kw):
    return emulate(prog.build(), timeout_s=10, **kw)


def test_exit_and_arch_name():
    p = MipsBEProg()
    p.exit(5)
    r = _run(p)
    assert r.arch == "mips" and r.stop_reason == "exit(5)" and r.error is None


def test_stdout_and_error_convention_in_big_endian_memory():
    p = MipsBEProg()
    msg, slot = p.d(b"hi"), p.d(b"\0" * 8)
    p.call("write", 1, msg, 2)
    p.sys(4000 + 999)                          # unknown syscall -> ENOSYS (89) with $a3 = 1
    p.store_reg(V0, slot)
    p.store_reg(A3, slot + 4)
    p.call("write", 1, slot, 8)
    p.exit(0)
    out = _run(p).stdout
    assert out[:2] == b"hi" and struct.unpack(">II", out[2:]) == (89, 1)


def test_tcp_connect_reads_a_big_endian_sockaddr():
    p = MipsBEProg()
    addr = p.d(MipsBEProg.sockaddr_in(C2_IP, C2_PORT))
    p.call("socket", 2, 2, 0)
    p.fd_from_result()
    p.li(5, addr); p.li(6, 16)
    p.call_keep_args("connect")
    p.exit(0)
    r = _run(p)
    assert {"op": "connect", "proto": "tcp", "family": "inet", "ip": C2_IP, "port": C2_PORT} in r.network


def test_dns_query_with_stack_passed_sendto_args():
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    p = MipsBEProg()
    dest = p.d(MipsBEProg.sockaddr_in("203.0.113.53", 53))
    q, buf = p.d(query), p.d(b"\0" * 128)
    p.call("socket", 2, 1, 0)
    p.fd_from_result()
    p.li(5, q); p.li(6, len(query)); p.li(7, 0)
    p.li(8, dest); p._w(0xAFA80010)              # sw $t0, 16($sp): 5th argument on the stack
    p.li(8, 16); p._w(0xAFA80014)                # 6th
    p.call_keep_args("sendto")
    p.li(5, buf); p.li(6, 128); p.li(7, 0)
    p.li(8, 0); p._w(0xAFA80010); p._w(0xAFA80014)
    p.call_keep_args("recvfrom")
    p.move(6, V0)
    p.li(4, 1); p.li(5, buf)
    p.call_keep_args("write")
    p.exit(0)
    r = _run(p)
    assert any(n["op"] == "dns_query" and n["domain"] == "c2.test" for n in r.network)
    assert bytes([192, 0, 2, 53]) in r.stdout


def test_files_and_chmod():
    p = MipsBEProg()
    path, body = p.cstr("/tmp/dropped"), p.d(b"payload")
    p.call("open", path, 0x101)
    p.fd_from_result()
    p.li(5, body); p.li(6, 7)
    p.call_keep_args("write")
    p.call("chmod", path, 0o755)
    p.exit(0)
    r = _run(p)
    assert r.files == {"/tmp/dropped": b"payload"} and r.file_modes == {"/tmp/dropped": 0o755}


def test_fork_then_execve_reads_big_endian_argv_pointers():
    p = MipsBEProg()
    sh, dashc, cmd = p.cstr("/bin/sh"), p.cstr("-c"), p.cstr("echo hi")
    argv = p.ptrs(sh, dashc, cmd, 0)
    parent = p.d(b"P")
    p.call("fork")
    p.bnez_v0("parent")
    p.call("execve", sh, argv, 0)
    p.exit(1)
    p.label("parent")
    p.call("write", 1, parent, 1)
    p.exit(0)
    r = _run(p)
    assert next(e for e in r.events if e["syscall"] == "execve")["argv"] == ["/bin/sh", "-c", "echo hi"]
    assert r.stdout == b"P" and r.stop_reason == "exit(0)"


def test_uname_reports_mips():
    p = MipsBEProg()
    buf = p.d(b"\0" * 390)
    p.call("uname", buf)
    p.call("write", 1, buf + 65 * 4, 4)
    p.exit(0)
    assert _run(p).stdout == b"mips"
