"""ElfSim: pure-emulation "detonator" for Linux ELF binaries (Mirai/Gafgyt-style IoT bots and
similar statically linked malware).

The sample is never executed. Unicorn interprets its instructions in-process and every
syscall is answered by an in-memory fake kernel (see kernel.py): there is no real network,
filesystem or process behind it. What the sample *tried* to do -- connect, resolve, send,
drop a file, fork, exec -- is recorded and reported.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shlex
from collections import Counter

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic, Result, ResultKeyValueSection, ResultSection, ResultTableSection, TableRow,
)
from assemblyline_v4_service.common.task import PARENT_RELATION

from elfsim_service.emulator import UnsupportedElf, emulate

MAX_ROWS = 30
MAX_EXTRACTED = 10
RECONNECT_THRESHOLD = 5
_LOCAL_NETS = [ipaddress.ip_network(n) for n in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

_STOP_TEXT = {
    "syscall_limit": "syscall budget exhausted (typical of a bot looping on its C2 / event loop)",
    "instruction_limit": "instruction budget exhausted (typical of a bot idling in a main loop)",
    "timeout": "emulation time limit reached",
    "execve": "sample exec'd another program",
    "fault": "emulation stopped on a CPU fault (see the error section)",
}


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast
            or any(addr in n for n in _LOCAL_NETS if n.version == addr.version))


def _preview(data: bytes, limit: int = 48) -> str:
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])
    return f"{data[:limit].hex()}  |{text}|"


class ElfSim(ServiceBase):
    def __init__(self, config=None) -> None:
        super().__init__(config)

    def start(self) -> None:
        self.log.info("ElfSim started (pure emulation, samples are never executed)")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        argv = ["/tmp/sample"] + shlex.split(request.get_param("arguments") or "")
        try:
            report = emulate(
                request.file_contents, argv=argv,
                max_instructions=request.get_param("max_instructions"),
                timeout_s=request.get_param("emulation_timeout_seconds"),
                max_syscalls=request.get_param("max_syscalls"),
            )
        except UnsupportedElf as e:
            # Not something we can emulate (other CPU, dynamic linking...). Silent on purpose:
            # this would fire on a large share of accepted files and isn't actionable.
            self.log.info(f"ElfSim skipping sample: {e}")
            request.result = result
            return

        self._summary(result, report)
        self._network(result, report)
        self._dns(result, report)
        self._sent_data(result, report)
        self._processes(result, report, argv)
        self._files(request, result, report, argv)
        self._fault(result, report)
        request.result = result
        self._save_report(request, report)

    # ------------------------------------------------------------------ sections
    def _summary(self, result: Result, report) -> None:
        stop = report.stop_reason
        if stop.startswith("exit("):
            stop = f"sample exited (exit code {stop[5:-1]})"
        abandoned = sum(1 for e in report.events if "abandoned" in e.get("note", ""))
        section = ResultKeyValueSection("Emulation summary")
        section.set_item("architecture", report.arch)
        section.set_item("entry_point", hex(report.entry))
        section.set_item("stopped_because", _STOP_TEXT.get(report.stop_reason, stop))
        section.set_item("syscalls_emulated", report.syscalls_total)
        if abandoned:
            section.set_item("idle_forked_paths_abandoned", abandoned)
        if report.unknown_syscalls:
            section.set_item("unimplemented_syscalls", ", ".join(sorted(report.unknown_syscalls)))
        section.set_item("runtime_seconds", round(report.elapsed, 2))
        section.set_heuristic(1, signature="emulation_completed")
        result.add_section(section)

    def _network(self, result: Result, report) -> None:
        has_dns = any(n["op"] == "dns_query" for n in report.network)
        rows: Counter = Counter()
        for n in report.network:
            if n["op"] in ("connect", "bind"):
                rows[(n["op"], n["proto"], n["ip"], n["port"])] += 1
        if not rows:
            return

        table = ResultTableSection("Network connections attempted (simulated, no real traffic)")
        heur = Heuristic(2)
        # TCP first, then by how often it was attempted.
        ordered = sorted(rows.items(), key=lambda kv: (kv[0][1] != "tcp", -kv[1]))
        shown = 0
        for (op, proto, ip, port), count in ordered:
            if shown >= MAX_ROWS:
                break
            sigs = []
            if op == "bind":
                sigs, note = ["bind_port"], "sample listens on this port (e.g. a single-instance lock)"
            elif _is_local(ip):
                continue  # loopback/private connects are clutter, not findings
            elif proto == "udp" and port == 53 and not has_dns:
                sigs, note = ["udp_probe"], ("UDP connect with no DNS query sent -- the usual "
                                             "local-address discovery trick, not a lookup")
            else:
                sigs, note = [f"{proto}_connect"], ""
                if proto == "tcp" and count >= RECONNECT_THRESHOLD:
                    # Our fake C2 answers EOF, so a benign client would give up; a bot retries.
                    sigs.append("persistent_reconnect")
                    note = f"reconnected {count} times: retry loop typical of a C2 client"
                table.add_tag("network.dynamic.ip", ip)
                table.add_tag("network.port", str(port))
                table.add_tag("network.protocol", proto)
            for sig in sigs:
                heur.add_signature_id(sig)
            table.add_row(TableRow(operation=op, protocol=proto, address=ip, port=port,
                                   times=count, note=note))
            shown += 1
        if not shown:
            return
        table.set_heuristic(heur)
        result.add_section(table)

    def _dns(self, result: Result, report) -> None:
        queries: Counter = Counter((n["domain"], n["qtype"]) for n in report.network
                                   if n["op"] == "dns_query")
        if not queries:
            return
        table = ResultTableSection("DNS lookups (answered with a documentation-range sinkhole)")
        for (domain, qtype), count in queries.most_common(MAX_ROWS):
            table.add_row(TableRow(domain=domain, record_type=qtype, times=count))
            table.add_tag("network.dynamic.domain", domain)
        table.set_heuristic(3, signature="dns_lookup")
        result.add_section(table)

    def _sent_data(self, result: Result, report) -> None:
        sends: Counter = Counter()
        for s in report.sent:
            if s["proto"] != "netlink" and s["ip"]:
                sends[(s["proto"], s["ip"], s["port"], s["data"])] += 1
        if not sends:
            return
        table = ResultTableSection("Data the sample sent (first bytes; hex | ascii)")
        for (proto, ip, port, data), count in sends.most_common(MAX_ROWS):
            table.add_row(TableRow(destination=f"{proto}://{ip}:{port}", bytes=len(data),
                                   times=count, preview=_preview(data)))
        table.set_heuristic(4, signature="data_sent")
        result.add_section(table)

    def _processes(self, result: Result, report, argv: list) -> None:
        rows: Counter = Counter()
        sigs: dict = {}
        commands: set = set()
        saw_fork = saw_setsid = False
        for e in report.events:
            if e["kind"] != "process":
                continue
            call = e["syscall"]
            if call == "execve":
                cmd = " ".join(e["argv"]) or e["path"]
                rows[("execve", cmd)] += 1
                sigs[("execve", cmd)] = "execve"
                commands.add(cmd)
            elif call == "prctl" and e.get("new_name"):
                rows[("process renamed", e["new_name"])] += 1
                sigs[("process renamed", e["new_name"])] = "process_rename"
            elif call == "ptrace":
                rows[("ptrace", "anti-debug probe")] += 1
                sigs[("ptrace", "anti-debug probe")] = "anti_debug"
            elif call == "kill":
                detail = f"signal {e['signal']} to pid {e['pid']}"
                rows[("kill", detail)] += 1
                sigs[("kill", detail)] = "kill_process"
            elif call == "fork" and "child_pid" in e:
                saw_fork = True
            elif call == "setsid":
                saw_setsid = True
        if saw_fork and saw_setsid:
            rows[("fork + setsid", "detaches from its parent and runs as a daemon")] += 1
            sigs[("fork + setsid", "detaches from its parent and runs as a daemon")] = "daemonize"
        if not rows:
            return

        table = ResultTableSection("Process activity")
        heur = Heuristic(5)
        for (action, detail), count in rows.most_common(MAX_ROWS):
            table.add_row(TableRow(action=action, detail=detail, times=count))
            heur.add_signature_id(sigs[(action, detail)])
        for cmd in commands:
            table.add_tag("dynamic.process.command_line", cmd)
        table.set_heuristic(heur)
        result.add_section(table)

    def _files(self, request: ServiceRequest, result: Result, report, argv: list) -> None:
        rows: list = []
        heur = Heuristic(6)
        extracted = 0

        for path, content in report.files.items():
            mode = report.file_modes.get(path)
            if not content and mode is None:
                continue
            executable = bool(mode and mode & 0o111)
            rows.append(TableRow(action="file written", path=path, size=len(content),
                                 mode=oct(mode) if mode is not None else ""))
            if content:
                heur.add_signature_id("dropped_file")
                if extracted < MAX_EXTRACTED:
                    out = os.path.join(self.working_directory, f"dropped_{extracted}.bin")
                    with open(out, "wb") as f:
                        f.write(content)
                    request.add_extracted(
                        out, os.path.basename(path) or f"dropped_{extracted}",
                        f"File written by the sample during emulation: {path}",
                        parent_relation=PARENT_RELATION.DYNAMIC,
                    )
                    extracted += 1
            if executable:
                heur.add_signature_id("made_executable")

        seen = set()
        for e in report.events:
            if e["kind"] != "file":
                continue
            key = (e["syscall"], e.get("path"), e.get("src"))
            if key in seen:
                continue
            seen.add(key)
            if e["syscall"] == "unlink":
                rows.append(TableRow(action="file deleted", path=e["path"], size="", mode=""))
                if e["path"] == argv[0]:
                    heur.add_signature_id("self_delete")
            elif e["syscall"] == "open" and e.get("note") == "special file opened":
                rows.append(TableRow(action="special file opened", path=e["path"], size="", mode=""))
                if e["path"].endswith("watchdog"):
                    heur.add_signature_id("watchdog_access")

        if not rows or not heur.signatures:
            return
        table = ResultTableSection("File system activity (simulated, in memory)")
        for row in rows[:MAX_ROWS]:
            table.add_row(row)
        table.set_heuristic(heur)
        result.add_section(table)

    def _fault(self, result: Result, report) -> None:
        if not report.error:
            return
        err = report.error
        body = f"{err.get('type', 'unknown error')} at pc={err.get('pc', '?')}"
        if err.get("bytes_at_pc"):
            body += f" (bytes at pc: {err['bytes_at_pc']})"
        body += (f"\nEmulation stopped after {report.syscalls_total} syscalls. This usually means "
                 "an unsupported instruction, TLS/thread setup, or a packed/self-modifying sample.")
        section = ResultSection("Emulation stopped on a CPU fault", body=body)
        section.set_heuristic(7, signature=err.get("type", "fault").replace(" ", "_"))
        result.add_section(section)

    # ------------------------------------------------------------------ raw report
    def _save_report(self, request: ServiceRequest, report) -> None:
        payload = {
            "architecture": report.arch, "entry_point": hex(report.entry),
            "stop_reason": report.stop_reason, "error": report.error,
            "syscalls_total": report.syscalls_total, "syscall_counts": report.syscall_counts,
            "unimplemented_syscalls": report.unknown_syscalls,
            "events": report.events, "events_dropped": report.events_dropped,
            "network": report.network,
            "sent": [{**s, "data": s["data"].hex()} for s in report.sent],
            "stdout": report.stdout.decode("latin-1"),
            "files": {p: len(c) for p, c in report.files.items()},
        }
        path = os.path.join(self.working_directory, "elfsim_report.json")
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        request.add_supplementary(path, "elfsim_report.json", "Full ElfSim emulation report")
