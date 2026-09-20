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
    blob = p.build(machine=40)   # EM_ARM

    class Req:
        file_contents = blob
        result = None

        def get_param(self, name):
            return {"arguments": "", "max_instructions": 1000,
                    "emulation_timeout_seconds": 5, "max_syscalls": 1000}[name]
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
                    "emulation_timeout_seconds": 10, "max_syscalls": 10000}[name]

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
