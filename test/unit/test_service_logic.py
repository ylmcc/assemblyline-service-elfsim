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


# ---- unsupported input is silent -----------------------------------------
def test_unsupported_elf_produces_no_result_sections():
    p = Prog()
    p.exit(0)
    blob = p.build(machine=8)   # EM_MIPS: not emulated yet

    class Req:
        file_contents = blob
        result = None
        def get_param(self, name):
            return {"arguments": "", "max_instructions": 1000,
                    "emulation_timeout_seconds": 5, "max_syscalls": 1000}[name]
    req = Req()
    ElfSim().execute(req)
    assert req.result.sections == []
