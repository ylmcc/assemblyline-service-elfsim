# ElfSim

Docker Hub: [kylemc54321/assemblyline-service-elfsim](https://hub.docker.com/r/kylemc54321/assemblyline-service-elfsim)

An [AssemblyLine 4](https://cybercentrecanada.github.io/assemblyline4_docs/) service that
"detonates" 32-bit Linux ELF malware **by emulation, never by execution**. It targets the
statically linked, stripped IoT bots (Mirai/Gafgyt-style loaders and their payloads) that
static analysis struggles with: instead of guessing from strings, it runs the sample's
instructions in [Unicorn](https://www.unicorn-engine.org/) and answers every system call from
an in-memory fake kernel, then reports what the sample *tried* to do.

## Safety model

- The sample's instructions are interpreted in-process by Unicorn. Nothing runs on the host CPU.
- There is no real network, filesystem, process table or clock behind the syscalls. A
  `connect()` is recorded and answered "success" from memory; a file write lands in a
  Python `bytearray`. The manifest sets `allow_internet_access: false`.
- Limits are enforced on instructions, syscalls, wall-clock time and mapped memory, so a
  sample that spins forever (typical of a bot's main loop) ends in a bounded time.
- Manual diagnosis on a real sample should still be done inside a locked-down container
  (`--network none --cap-drop ALL --security-opt no-new-privileges --read-only`, memory and
  PID limits, sample mounted read-only) as defence in depth against an emulator bug.

## What it reports

| Section | Notes |
|---|---|
| Emulation summary | architecture, entry point, why emulation stopped, syscalls emulated |
| Network connections attempted | TCP/UDP connects and binds; tags `network.dynamic.ip`, `network.port`, `network.protocol` |
| DNS lookups | domain parsed from the query and answered with a documentation-range sinkhole so the sample carries on to its real C2 connect; tags `network.dynamic.domain` |
| What the sample sent | a readable transcript per distinct conversation: control bytes as `\xNN`, adjacent TCP sends joined, repeats as `xN`, plus the printable text found (hex only in the supplementary JSON) |
| Process activity | `fork`/`setsid` daemonising, `prctl` renames, `execve` (with argv), `kill`, `ptrace` probes |
| File system activity | files written (extracted with `PARENT_RELATION.DYNAMIC`), `chmod +x`, deletes, watchdog opens |
| Emulation stopped on a CPU fault | faulting pc, instruction bytes and the reason |

The MIPS port was validated on a real static uClibc `busybox` (echo, uname, cat, ls, sleep), not only
synthetic fixtures.

A full event log is attached as the supplementary file `elfsim_report.json`.

Heuristics are deliberately quiet. Things a benign daemon also does (DNS lookups, `fork` +
`setsid`, renaming itself, writing a file) are shown but score 0. Score goes to combinations
that mean something: exec'ing a program, writing a file then making it executable, deleting
itself, and a persistent reconnect loop against the same public endpoint.

## How it works

`fork()` is handled by snapshotting CPU, memory and the fd table, running the child path
first, and rewinding to the parent path when the child exits, execs or exhausts its syscall
budget, so both halves of `if (fork() == 0)` are explored and an idle daemon loop cannot
starve the rest of the program. Unknown syscalls are answered `-ENOSYS` and reported.

## Submission parameters

| Name | Default | Purpose |
|---|---|---|
| `arguments` | empty | extra `argv[1:]` for the sample (loaders often pass an arch name) |
| `max_instructions` | 50,000,000 | instruction budget per execution path |
| `emulation_timeout_seconds` | 60 | wall-clock limit |
| `max_syscalls` | 200,000 | total syscall budget |

## Limitations

- 32-bit little-endian **x86** and **MIPS (o32)** static binaries only. Other CPUs, 64-bit ELFs,
  big-endian MIPS, N32/MIPS16/microMIPS and dynamically linked binaries are not emulated; the
  result carries a collapsed, unscored note saying why (no heuristic, so no noise).
- ARM, PowerPC and m68k are supported by Unicorn and would each need an `Arch` entry in
  `elfsim_service/arch.py` (register map, syscall table, ABI constants); big-endian MIPS needs
  byte-order support in the fake kernel. SH4 is not supported by Unicorn.
- Truncated files are loaded the way a kernel would (missing bytes read as zero) and the summary
  says so. A UPX-packed sample must be complete for any unpacker to work on it.
- Memory is snapshotted at `fork()`, but the fake filesystem and network log are shared.
- Threads (`clone` with `CLONE_VM`) are not emulated. On x86, TLS setup (`set_thread_area`) returns
  `-ENOSYS` (MIPS handles it via the CP0 UserLocal register); a sample that needs either stops with
  a fault and says so.

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install assemblyline-v4-service assemblyline-service-utilities unicorn pyelftools pytest pyyaml
.venv/bin/pytest test/
```

The tests build tiny synthetic i386 and MIPS ELF files from a handful of opcodes
(`test/unit/elfbuilder.py`, `test/unit/mipsbuilder.py`, `test/unit/demo_bot.py`). They are inert fixtures, contain no real
malware and use only RFC 5737 documentation addresses and `.test` hostnames.

## Licence

MIT. Depends on [Unicorn](https://github.com/unicorn-engine/unicorn) and
[pyelftools](https://github.com/eliben/pyelftools) via pip (not vendored).
