import struct

import pytest

from elfsim_service.emulator import UnsupportedElf, emulate
from test.unit.armbuilder import ArmProg

C2_IP, C2_PORT = "198.51.100.7", 4444


def _run(prog, **kw):
    return emulate(prog.build(), timeout_s=10, **kw)


def test_exit_code_and_arch_name():
    p = ArmProg()
    p.exit(9)
    r = _run(p)
    assert r.arch == "arm" and r.stop_reason == "exit(9)" and r.error is None


def test_stdout_is_captured_and_execution_continues_after_svc():
    p = ArmProg()
    msg = p.d(b"hello")
    p.call("write", 1, msg, 5)
    p.call("write", 1, msg, 2)
    p.exit(0)
    assert _run(p).stdout == b"hellohe"


def test_errors_are_negative_errno_in_r0():
    p = ArmProg()
    slot = p.d(b"\0" * 4)
    p.sys(9999)
    p.store_r0(slot)
    p.call("write", 1, slot, 4)
    p.exit(0)
    assert struct.unpack("<i", _run(p).stdout)[0] == -38          # ENOSYS


def test_tcp_connect_is_recorded():
    p = ArmProg()
    addr = p.d(ArmProg.sockaddr_in(C2_IP, C2_PORT))
    p.call("socket", 2, 1, 0)
    p.li(1, addr); p.li(2, 16)
    p.call_keep_args("connect")                                   # fd is still in r0
    p.exit(0)
    assert {"op": "connect", "proto": "tcp", "family": "inet", "ip": C2_IP, "port": C2_PORT} in _run(p).network


def test_dns_query_with_six_register_arguments_and_the_sender_is_reported():
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    p = ArmProg()
    dest = p.d(ArmProg.sockaddr_in("203.0.113.53", 53))
    q, buf, src, srclen = p.d(query), p.d(b"\0" * 128), p.d(b"\0" * 16), p.d(struct.pack("<I", 16))
    p.call("socket", 2, 2, 0)
    p.li(1, q); p.li(2, len(query)); p.li(3, 0); p.li(4, dest); p.li(5, 16)
    p.call_keep_args("sendto")
    p.li(0, 3)                                                    # r0 held sendto's result; reload the fd
    p.li(1, buf); p.li(2, 128); p.li(3, 0); p.li(4, src); p.li(5, srclen)
    p.call_keep_args("recvfrom")
    p.call("write", 1, src, 8)
    p.exit(0)
    r = _run(p)
    assert any(n["op"] == "dns_query" and n["domain"] == "c2.test" for n in r.network)
    assert r.stdout == struct.pack("<H", 2) + struct.pack(">H", 53) + bytes([203, 0, 113, 53])


def test_files_and_chmod():
    p = ArmProg()
    path, body = p.cstr("/tmp/dropped"), p.d(b"payload")
    p.call("open", path, 0o101)
    p.li(1, body); p.li(2, 7)
    p.call_keep_args("write")
    p.call("chmod", path, 0o755)
    p.exit(0)
    r = _run(p)
    assert r.files == {"/tmp/dropped": b"payload"} and r.file_modes == {"/tmp/dropped": 0o755}


def test_forked_parent_gets_the_child_pid_and_the_syscall_runs_once():
    p = ArmProg()
    slot = p.d(b"\0" * 4)
    p.call("fork")
    p.bnez_r0("parent")
    p.exit(0)
    p.label("parent")
    p.store_r0(slot)
    p.call("write", 1, slot, 4)
    p.exit(0)
    r = _run(p)
    assert struct.unpack("<I", r.stdout)[0] == 1001
    assert r.syscall_counts["fork"] == 1 and r.unknown_syscalls == {}


def test_tls_through_the_private_set_tls_syscall_and_the_thread_pointer_register():
    p = ArmProg()
    slot = p.d(b"\0" * 4)
    p.sys(0x0F0005, 0x12345678)                                   # __ARM_NR_set_tls
    p.raw_words(0xEE1D0F70)                                       # mrc p15, 0, r0, c13, c0, 3
    p.store_r0(slot)
    p.call("write", 1, slot, 4)
    p.exit(0)
    assert struct.unpack("<I", _run(p).stdout)[0] == 0x12345678


def test_the_kernel_user_helper_page_provides_get_tls_and_cmpxchg():
    p = ArmProg()
    tls, word, out = 0xCAFE0000, p.d(struct.pack("<I", 7)), p.d(b"\0" * 12)
    p.sys(0x0F0005, tls)
    p.li(3, 0xFFFF0FE0); p.raw_words(0xE12FFF33)                  # blx r3 -> __kuser_get_tls
    p.store_r0(out)
    p.li(0, 7); p.li(1, 99); p.li(2, word)                        # cmpxchg(old=7, new=99, ptr)
    p.li(3, 0xFFFF0FC0); p.raw_words(0xE12FFF33)                  # blx r3 -> __kuser_cmpxchg
    p.store_r0(out + 4)
    p.li(1, word); p.raw_words(0xE5910000)                        # ldr r0, [r1]
    p.store_r0(out + 8)
    p.call("write", 1, out, 12)
    p.exit(0)
    got_tls, swap_result, new_value = struct.unpack("<III", _run(p).stdout)
    assert (got_tls, swap_result, new_value) == (tls, 0, 99)


def test_uname_reports_armv7l():
    p = ArmProg()
    buf = p.d(b"\0" * 390)
    p.call("uname", buf)
    p.call("write", 1, buf + 65 * 4, 5)
    p.exit(0)
    assert _run(p).stdout == b"armv7"


def test_big_endian_arm_is_reported_as_unsupported():
    p = ArmProg()
    p.exit(0)
    blob = bytearray(p.build())
    blob[5] = 2
    fields = struct.unpack("<HHIIIIIHHHHHH", bytes(blob[16:52]))
    blob[16:52] = struct.pack(">HHIIIIIHHHHHH", *fields)
    with pytest.raises(UnsupportedElf, match="big-endian is not emulated"):
        emulate(bytes(blob))
