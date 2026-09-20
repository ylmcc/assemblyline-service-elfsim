import struct

import pytest

from elfsim_service.emulator import UnsupportedElf, emulate
from test.unit.mipsbuilder import A0, A3, V0, MipsProg

C2_IP, C2_PORT = "198.51.100.7", 4444   # RFC 5737 documentation range


def _run(prog: MipsProg, **kw):
    return emulate(prog.build(), timeout_s=10, **kw)


def test_exit_code_is_reported():
    p = MipsProg()
    p.exit(7)
    r = _run(p)
    assert r.stop_reason == "exit(7)" and r.error is None and r.arch == "mipsel"


def test_execution_continues_after_a_syscall_and_stdout_is_captured():
    p = MipsProg()
    msg = p.d(b"hello")
    p.call("write", 1, msg, 5)
    p.exit(0)
    assert _run(p).stdout == b"hello"


def test_error_convention_is_a3_flag_plus_positive_mips_errno():
    p = MipsProg()
    slot = p.d(b"\0" * 8)
    p.sys(4000 + 999)                       # not a real syscall -> ENOSYS
    p.store_reg(V0, slot)
    p.store_reg(A3, slot + 4)
    p.call("write", 1, slot, 8)
    p.exit(0)
    v0, a3 = struct.unpack("<II", _run(p).stdout)
    assert (v0, a3) == (89, 1)              # MIPS ENOSYS is 89 (i386: 38), flagged in $a3


def test_successful_syscall_clears_the_error_flag():
    p = MipsProg()
    slot, msg = p.d(b"\xff" * 8), p.d(b"hi")
    p.call("write", 1, msg, 2)              # succeeds, returns 2
    p.store_reg(V0, slot)
    p.store_reg(A3, slot + 4)
    p.call("write", 1, slot, 8)
    p.exit(0)
    assert struct.unpack("<II", _run(p).stdout[2:]) == (2, 0)     # first 2 bytes are "hi"


def test_tcp_socket_uses_mips_socket_type_numbers():
    p = MipsProg()
    addr = p.d(MipsProg.sockaddr_in(C2_IP, C2_PORT))
    p.call("socket", 2, 2, 0)               # AF_INET, SOCK_STREAM (== 2 on MIPS)
    p.fd_from_result()
    p.li(5, addr); p.li(6, 16)
    p.call_keep_args("connect")
    p.exit(0)
    r = _run(p)
    assert {"op": "connect", "proto": "tcp", "family": "inet", "ip": C2_IP, "port": C2_PORT} in r.network


def test_dns_query_sent_with_stack_passed_sendto_args_is_parsed_and_answered():
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    p = MipsProg()
    dest = p.d(MipsProg.sockaddr_in("203.0.113.53", 53))
    q, buf = p.d(query), p.d(b"\0" * 128)
    p.call("socket", 2, 1, 0)               # SOCK_DGRAM == 1 on MIPS
    p.fd_from_result()
    # sendto(fd, q, len, 0, dest, 16): the 5th and 6th arguments go on the stack
    p.li(5, q); p.li(6, len(query)); p.li(7, 0)
    p.li(8, dest); p._w(0xAFA80010)         # sw $t0, 16($sp)
    p.li(8, 16); p._w(0xAFA80014)           # sw $t0, 20($sp)
    p.call_keep_args("sendto")
    p.li(5, buf); p.li(6, 128); p.li(7, 0)
    p.li(8, 0); p._w(0xAFA80010); p._w(0xAFA80014)
    p.call_keep_args("recvfrom")            # v0 = reply length
    p.move(6, V0)                           # a2 = length
    p.li(4, 1); p.li(5, buf)
    p.call_keep_args("write")
    p.exit(0)
    r = _run(p)
    assert any(n["op"] == "dns_query" and n["domain"] == "c2.test" for n in r.network)
    assert bytes([192, 0, 2, 53]) in r.stdout


def test_open_uses_mips_flag_values_and_files_are_captured_in_memory():
    p = MipsProg()
    path, body = p.cstr("/tmp/dropped"), p.d(b"payload")
    p.call("open", path, 0x101)             # O_WRONLY | O_CREAT (0x100 on MIPS; 0x40 on i386)
    p.fd_from_result()
    p.li(5, body); p.li(6, 7)
    p.call_keep_args("write")
    p.call("chmod", path, 0o755)
    p.exit(0)
    r = _run(p)
    assert r.files == {"/tmp/dropped": b"payload"} and r.file_modes == {"/tmp/dropped": 0o755}


def test_fork_child_runs_first_then_the_parent_path_resumes():
    p = MipsProg()
    sh, dashc, cmd = p.cstr("/bin/sh"), p.cstr("-c"), p.cstr("echo hi")
    argv = p.ptrs(sh, dashc, cmd, 0)
    parent_msg = p.d(b"P")
    p.call("fork")
    p.bnez_v0("parent")
    p.call("execve", sh, argv, 0)           # child
    p.exit(1)
    p.label("parent")
    p.call("write", 1, parent_msg, 1)
    p.exit(0)
    r = _run(p)
    execve = next(e for e in r.events if e["syscall"] == "execve")
    assert execve["argv"] == ["/bin/sh", "-c", "echo hi"]
    assert r.stdout == b"P" and r.stop_reason == "exit(0)"


def test_infinite_loop_hits_the_instruction_limit():
    p = MipsProg()
    p.label("spin")
    p.b("spin")
    r = emulate(p.build(), max_instructions=10_000, timeout_s=10)
    assert r.stop_reason == "instruction_limit"


def test_big_endian_and_n32_mips_are_reported_as_unsupported():
    p = MipsProg()
    p.exit(0)
    be = bytearray(p.build())
    be[5] = 2                                # EI_DATA = big-endian ...
    fields = struct.unpack("<HHIIIIIHHHHHH", bytes(be[16:52]))
    be[16:52] = struct.pack(">HHIIIIIHHHHHH", *fields)   # ... and a header that really is big-endian
    with pytest.raises(UnsupportedElf, match="little-endian"):
        emulate(bytes(be))
    with pytest.raises(UnsupportedElf, match="N32"):
        emulate(p.build(flags=0x1000 | 0x20))
    with pytest.raises(UnsupportedElf, match="microMIPS"):
        emulate(p.build(flags=0x02000000))


def test_uname_reports_the_emulated_architecture():
    p = MipsProg()
    buf = p.d(b"\0" * 390)
    p.call("uname", buf)
    p.call("write", 1, buf + 65 * 4, 4)       # machine is the 5th field of struct utsname
    p.exit(0)
    assert _run(p).stdout == b"mips"


def test_truncated_file_is_loaded_leniently_and_explained():
    p = MipsProg()
    p.exit(0)
    full = p.build()
    r = emulate(full[:0x110], timeout_s=5)      # cut off inside the code: entry (0x100) still present
    assert r.warnings == [] or all("truncated" not in w for w in r.warnings)
    # header claims more file bytes than exist and the entry point lies beyond the end
    cut = bytearray(full[:0x80])
    r = emulate(bytes(cut), timeout_s=5)
    assert any("truncated" in w and "entry point" in w for w in r.warnings)
    assert r.stop_reason == "fault"


def test_upx_marker_in_the_headers_gets_an_unpacker_hint():
    p = MipsProg()
    p.exit(0)
    blob = bytearray(p.build())
    blob[0x78:0x7C] = b"UPX!"                   # where UPX puts its l_info magic
    r = emulate(bytes(blob), timeout_s=5)
    assert any("UPX-packed" in w for w in r.warnings)
