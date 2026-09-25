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
        emulate(p.build(machine=20))   # EM_PPC


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


def _sender(*chunks):
    """socket + connect, then one sendto() per chunk (NULL destination)."""
    p = Prog()
    addr = p.d(Prog.sockaddr_in(C2_IP, C2_PORT))
    addrs = [p.d(c) for c in chunks]
    p.sys(359, 2, 1, 0)                       # socket
    p.ebx_from_eax()
    p.mov(1, addr); p.mov(2, 16); p.mov(0, 362)
    p.raw(b"\xcd\x80")                        # connect
    for a, c in zip(addrs, chunks):
        p.mov(1, a); p.mov(2, len(c)); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 369)
        p.raw(b"\xcd\x80")                    # sendto(fd, chunk, len, 0, NULL, 0)
    p.exit(0)
    return p


def test_sends_on_one_socket_become_one_ordered_conversation_with_repeats_collapsed():
    r = _run(_sender(b"\x00\x00\x00\x01", b"\x04px86", b"\x00\x00", b"\x00\x00", b"\x00\x00"))
    (conv,) = r.sent
    assert (conv["proto"], conv["ip"], conv["port"]) == ("tcp", C2_IP, C2_PORT)
    assert conv["messages"] == [[b"\x00\x00\x00\x01", 1], [b"\x04px86", 1], [b"\x00\x00", 3]]
    assert conv["total_bytes"] == 4 + 5 + 6


def test_a_heartbeat_loop_cannot_push_out_the_first_messages():
    p = Prog()
    addr = p.d(Prog.sockaddr_in(C2_IP, C2_PORT))
    reg, beat = p.d(b"\x04px86"), p.d(b"\x00\x00")
    counter = p.d(struct.pack("<I", 300))      # 300 heartbeats: well past the old 200-entry cap
    p.sys(359, 2, 1, 0)
    p.ebx_from_eax()
    p.mov(1, addr); p.mov(2, 16); p.mov(0, 362)
    p.raw(b"\xcd\x80")                         # connect
    p.mov(1, reg); p.mov(2, 5); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 369)
    p.raw(b"\xcd\x80")                         # registration
    p.label("beat")
    p.mov(1, beat); p.mov(2, 2); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 369)
    p.raw(b"\xcd\x80")                         # heartbeat (ebx still holds the fd)
    p.loop_dec(counter, "beat")
    p.exit(0)
    (conv,) = _run(p).sent
    assert conv["messages"] == [[b"\x04px86", 1], [b"\x00\x00", 300]]


def test_recvfrom_reports_the_sender_so_resolvers_accept_the_answer():
    """musl's resolver drops replies whose source address isn't the server it queried."""
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    p = Prog()
    dest = p.d(Prog.sockaddr_in("203.0.113.53", 53))
    q, buf, src, srclen = p.d(query), p.d(b"\0" * 128), p.d(b"\0" * 16), p.d(struct.pack("<I", 16))
    p.sys(359, 2, 2, 0)
    p.ebx_from_eax()
    p.mov(1, q); p.mov(2, len(query)); p.mov(6, 0); p.mov(7, dest); p.mov(5, 16); p.mov(0, 369)
    p.raw(b"\xcd\x80")                                  # sendto
    p.mov(1, buf); p.mov(2, 128); p.mov(6, 0); p.mov(7, src); p.mov(5, srclen); p.mov(0, 371)
    p.raw(b"\xcd\x80")                                  # recvfrom(fd, buf, 128, 0, &src, &len)
    p.sys(4, 1, src, 8)
    p.exit(0)
    assert _run(p).stdout == struct.pack("<H", 2) + struct.pack(">H", 53) + bytes([203, 0, 113, 53])


def test_readlink_of_proc_self_exe_returns_the_programs_own_path():
    p = Prog()
    link, buf = p.cstr("/proc/self/exe"), p.d(b"\0" * 64)
    p.sys(85, link, buf, 63)                     # readlink(path, buf, size) -> length in eax
    p.edx_from_eax()
    p.sys(4, 1, buf)                             # write(1, buf, edx)
    p.exit(0)
    assert emulate(p.build(), argv=["/tmp/robben"], timeout_s=10).stdout == b"/tmp/robben"


def test_a_crash_in_a_forked_child_only_kills_that_path():
    p = Prog()
    p.sys(2)                                             # fork
    p.jnz("parent")
    p.raw(b"\xa1" + struct.pack("<I", 0xDEADBEEF))       # child: mov eax, [0xdeadbeef] -> fault
    p.label("parent")
    msg = p.d(b"P")
    p.sys(4, 1, msg, 1)
    p.exit(0)
    r = _run(p)
    assert r.stdout == b"P" and r.stop_reason == "exit(0)" and r.error is None
    assert len(r.child_crashes) == 1 and "unmapped" in r.child_crashes[0]["type"]
    assert any("forked path crashed" in e.get("note", "") for e in r.events)


def test_a_crash_on_the_main_path_is_still_reported_as_a_fault():
    p = Prog()
    p.raw(b"\xa1" + struct.pack("<I", 0xDEADBEEF))
    r = _run(p)
    assert r.stop_reason == "fault" and r.child_crashes == []


def test_raw_socket_sends_are_labelled_raw_not_tcp():
    p = Prog()
    dest, pkt = p.d(Prog.sockaddr_in("198.51.100.9", 23)), p.d(b"E\x00\x00\x28" + b"\0" * 36)
    p.sys(359, 2, 3, 255)                       # socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    p.ebx_from_eax()
    p.mov(1, pkt); p.mov(2, 40); p.mov(6, 0); p.mov(7, dest); p.mov(5, 16); p.mov(0, 369)
    p.raw(b"\xcd\x80")                          # sendto
    p.exit(0)
    (conv,) = _run(p).sent
    assert conv["proto"] == "raw" and conv["ip"] == "198.51.100.9"


# ---- filesystem realism: what a bot checks before it installs itself ------------------
def _errno_of(p: Prog, nr: int, *args: int) -> None:
    """Run a syscall and write its raw 4-byte return value to stdout."""
    slot = p.d(b"\0" * 4)
    p.sys(nr, *args)
    p.store_eax(slot)
    p.sys(4, 1, slot, 4)


def test_the_sample_can_read_its_own_binary_to_copy_itself():
    p = Prog()
    path, buf = p.cstr("/tmp/sample"), p.d(b"\0" * 4)
    p.sys(5, path, 0)            # open(argv[0], O_RDONLY)
    p.ebx_from_eax()
    p.mov(1, buf); p.mov(2, 4); p.mov(0, 3)
    p.raw(b"\xcd\x80")           # read(fd, buf, 4)
    p.sys(4, 1, buf, 4)
    p.exit(0)
    assert _run(p).stdout == b"\x7fELF"


def test_its_own_binary_cannot_be_opened_for_writing():
    p = Prog()
    _errno_of(p, 5, p.cstr("/tmp/sample"), 0o1)   # open(argv[0], O_WRONLY)
    p.exit(0)
    r = _run(p)
    assert struct.unpack("<i", r.stdout)[0] == -26     # ETXTBSY
    assert r.files == {}


def test_after_deleting_itself_its_binary_is_gone():
    p = Prog()
    path = p.cstr("/tmp/sample")
    p.sys(10, path)              # unlink(argv[0])
    _errno_of(p, 33, path, 0)    # access(argv[0], F_OK)
    p.exit(0)
    r = _run(p)
    assert struct.unpack("<i", r.stdout)[0] == -2
    assert next(e for e in r.events if e["syscall"] == "unlink")["existed"] is True


def test_dev_shm_is_an_ordinary_directory_not_a_device():
    p = Prog()
    _errno_of(p, 33, p.cstr("/dev/shm/.cache-1"), 0)   # "am I already installed here?"
    path, body = p.cstr("/dev/shm/.cache-1"), p.d(b"copy")
    p.sys(5, path, 0o101)
    p.ebx_from_eax()
    p.mov(1, body); p.mov(2, 4); p.mov(0, 4)
    p.raw(b"\xcd\x80")
    p.exit(0)
    r = _run(p)
    assert struct.unpack("<i", r.stdout)[0] == -2
    assert r.files == {"/dev/shm/.cache-1": b"copy"}


@pytest.mark.parametrize("path", ["/etc/cron.d", "/etc/init.d", "/etc/systemd/system", "/var/spool/cron",
                                  "/etc/dhcp/dhclient-exit-hooks.d", "/etc/udev/rules.d"])
def test_persistence_directories_exist(path):
    p = Prog()
    _errno_of(p, 33, p.cstr(path), 0)
    p.exit(0)
    assert struct.unpack("<i", _run(p).stdout)[0] == 0


def test_appending_to_etc_crontab_keeps_its_existing_content():
    p = Prog()
    path, line = p.cstr("/etc/crontab"), p.d(b"@reboot x\n")
    p.sys(5, path, 0o2001)       # open(O_WRONLY|O_APPEND)
    p.ebx_from_eax()
    p.mov(1, line); p.mov(2, 10); p.mov(0, 4)
    p.raw(b"\xcd\x80")
    p.exit(0)
    content = _run(p).files["/etc/crontab"]
    assert content.startswith(b"SHELL=/bin/sh\n") and content.endswith(b"@reboot x\n")


def test_mkdir_creates_a_directory_that_then_exists():
    p = Prog()
    path = p.cstr("/opt/.hidden")
    _errno_of(p, 33, path, 0)
    p.sys(39, path, 0o755)       # mkdir
    _errno_of(p, 33, path, 0)
    _errno_of(p, 39, path, 0o755)
    p.exit(0)
    assert struct.unpack("<3i", _run(p).stdout) == (-2, 0, -17)   # ENOENT, exists, EEXIST


def test_access_probes_for_missing_paths_are_logged_once():
    p = Prog()
    path = p.cstr("/etc/some-missing-dir")
    p.sys(33, path, 0)
    p.sys(33, path, 0)
    p.exit(0)
    probes = [e for e in _run(p).events if e["syscall"] == "access"]
    assert probes == [{"kind": "file", "syscall": "access", "path": "/etc/some-missing-dir",
                       "note": "probed, does not exist"}]


# ---- event log: one busy loop must not crowd everything else out ----------------------
def test_identical_events_collapse_into_one_with_a_repeat_count():
    p = Prog()
    counter = p.d(struct.pack("<I", 6000))
    p.label("loop")
    p.sys(37, 1, 0)              # kill(1, 0): a liveness probe loop, as real bots do
    p.loop_dec(counter, "loop")
    msg = p.cstr("/etc/after-the-loop")
    p.sys(33, msg, 0)
    p.exit(0)
    r = _run(p)
    kills = [e for e in r.events if e["syscall"] == "kill"]
    assert len(kills) == 1 and kills[0]["repeat"] == 6000
    assert any(e.get("path") == "/etc/after-the-loop" for e in r.events)


def test_one_syscall_cannot_fill_the_whole_event_log():
    from elfsim_service import kernel as K
    from elfsim_service.arch import ARCHES
    k = K.FakeKernel(None, next(iter(ARCHES.values())), brk_base=0x10000, stack_low=0)
    for pid in range(K.MAX_EVENTS * 2):
        k.log("process", "kill", pid=pid, signal=9)
    k.log("file", "open", path="/etc/rc.local")
    assert sum(e["syscall"] == "kill" for e in k.events) == K.MAX_EVENTS_PER_SYSCALL
    assert k.events[-1]["path"] == "/etc/rc.local"


def test_a_slow_child_path_is_abandoned_on_time_even_under_its_syscall_budget(monkeypatch):
    import functools
    from elfsim_service import emulator
    monkeypatch.setattr(emulator, "FakeKernel",
                        functools.partial(emulator.FakeKernel, max_path_syscalls=10 ** 9))
    p = Prog()
    msg = p.d(b"P")
    p.sys(2)                     # fork
    p.jnz("parent")
    p.label("spin")
    p.sys(158)                   # child: an idle loop that never runs out of syscall budget
    p.jmp("spin")
    p.label("parent")
    p.sys(4, 1, msg, 1)
    p.exit(0)
    r = emulate(p.build(), timeout_s=8, max_syscalls=10 ** 9)
    assert r.stdout == b"P"
    assert any("time budget" in e.get("note", "") for e in r.events)


def test_a_child_forked_late_still_gets_its_own_syscall_budget():
    p = Prog()
    counter, msg = p.d(struct.pack("<I", 25_000)), p.d(b"C")
    p.label("busy")
    p.sys(158)                   # the root path runs a while before forking
    p.loop_dec(counter, "busy")
    p.sys(2)                     # fork
    p.jnz("parent")
    p.sys(4, 1, msg, 1)          # the child must get to run, not be abandoned at once
    p.exit(0)
    p.label("parent")
    p.exit(0)
    assert _run(p, max_syscalls=10 ** 6).stdout == b"C"
