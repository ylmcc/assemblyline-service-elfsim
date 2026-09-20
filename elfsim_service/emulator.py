"""ELF loader + Unicorn run loop. Never executes anything on the real CPU: Unicorn interprets
the guest's instructions and every syscall is answered by ``FakeKernel``.
"""
from __future__ import annotations

import io
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_INTR, Uc, UcError, UC_PROT_ALL

from elfsim_service.arch import ARCHES, Arch
from elfsim_service.kernel import PAGE, FakeKernel

STACK_SIZE = 0x100000
MAX_IMAGE_BYTES = 128 * 1024 * 1024

AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ, AT_ENTRY = 0, 3, 4, 5, 6, 9
AT_UID, AT_EUID, AT_GID, AT_EGID, AT_RANDOM = 11, 12, 13, 14, 25

_UC_ERRORS = {
    6: "read from unmapped memory", 7: "write to unmapped memory",
    8: "instruction fetch from unmapped memory", 10: "invalid instruction",
    11: "unmapped/protected memory access", 12: "write to protected memory",
    13: "read from protected memory", 14: "fetch from protected memory",
    21: "unaligned access", 20: "instruction limit exceeded", 15: "exception",
}


class UnsupportedElf(Exception):
    """The file is an ELF ElfSim cannot emulate (wrong arch, dynamic, malformed...)."""


@dataclass
class EmulationReport:
    arch: str
    entry: int
    stop_reason: str = ""
    error: Optional[dict] = None
    events: list = field(default_factory=list)
    events_dropped: int = 0
    network: list = field(default_factory=list)
    files: dict = field(default_factory=dict)       # path -> bytes the sample wrote
    file_modes: dict = field(default_factory=dict)  # path -> last chmod mode
    stdout: bytes = b""
    sent: list = field(default_factory=list)  # one conversation per socket: [{proto, ip, port, messages: [[bytes, repeats]...], total_bytes}]
    received: list = field(default_factory=list)  # bytes a relayed remote end sent back
    syscall_counts: dict = field(default_factory=dict)
    unknown_syscalls: dict = field(default_factory=dict)
    syscalls_total: int = 0
    open_counts: dict = field(default_factory=dict)  # most-opened paths (diagnostics)
    elapsed: float = 0.0
    warnings: list = field(default_factory=list)  # oddities in the file itself (e.g. truncated segments)


def _align_down(v: int) -> int:
    return v & ~(PAGE - 1)


def _align_up(v: int) -> int:
    return (v + PAGE - 1) & ~(PAGE - 1)


def _describe_fault(uc: Uc, arch: Arch, e: UcError) -> dict:
    info = {"type": _UC_ERRORS.get(e.errno, f"unicorn error {e.errno}")}
    try:
        pc = uc.reg_read(arch.pc_reg)
        info["pc"] = hex(pc)
        info["bytes_at_pc"] = bytes(uc.mem_read(pc, 8)).hex()
    except UcError:
        pass
    return info


def emulate(data: bytes, *, argv: Optional[list] = None, max_instructions: int = 50_000_000,
            timeout_s: float = 30.0, max_syscalls: int = 200_000,
            relay=None) -> EmulationReport:
    started = time.monotonic()
    try:
        elf = ELFFile(io.BytesIO(data))
        machine = elf.header["e_machine"]
        arch = ARCHES.get(machine)
        if arch is None:
            raise UnsupportedElf(f"unsupported machine {machine}")
        if elf.elfclass != 32 or not elf.little_endian:
            raise UnsupportedElf(f"unsupported ELF variant for {machine}: only 32-bit little-endian "
                                 "is emulated (no 64-bit or big-endian yet)")
        if machine == "EM_MIPS":
            flags = elf.header["e_flags"]
            if flags & 0x20:      # EF_MIPS_ABI2: the N32 ABI has a different syscall interface
                raise UnsupportedElf("MIPS N32 ABI is not supported (o32 only)")
            if flags & 0x06000000:  # EF_MIPS_ARCH_ASE_M16 | EF_MIPS_ARCH_ASE_MICROMIPS
                raise UnsupportedElf("MIPS16/microMIPS code is not supported")
        if elf.header["e_type"] != "ET_EXEC":
            raise UnsupportedElf(f"unsupported ELF type {elf.header['e_type']}")
        segments = [s for s in elf.iter_segments()]
        if any(s["p_type"] == "PT_INTERP" for s in segments):
            raise UnsupportedElf("dynamically linked (no dynamic loader is emulated)")
        loads = [s for s in segments if s["p_type"] == "PT_LOAD"]
        entry = elf.header["e_entry"]
        phoff, phnum = elf.header["e_phoff"], elf.header["e_phnum"]
    except (ELFError, KeyError, struct.error) as e:
        raise UnsupportedElf(f"malformed ELF: {e}")
    if not loads:
        raise UnsupportedElf("no loadable segments")

    uc = Uc(arch.uc_arch, arch.uc_mode)

    # ---- map segments (page runs not already mapped by an earlier segment)
    mapped_pages: set = set()
    image_end = 0
    phdr_addr = None
    warnings: list = []
    for seg in loads:
        vaddr, memsz, filesz, off = seg["p_vaddr"], seg["p_memsz"], seg["p_filesz"], seg["p_offset"]
        if filesz > memsz:
            raise UnsupportedElf("segment file size exceeds its memory size")
        if off + filesz > len(data):
            # A real kernel maps what the file has and zero-fills the rest, so do the same, but
            # say so: the file is shorter than its headers claim (truncated download, or a
            # packer such as UPX that lies about sizes), so emulation may end early.
            warnings.append(f"segment at {hex(vaddr)} claims {filesz} file bytes but only "
                            f"{max(0, len(data) - off)} exist; the missing {min(filesz, off + filesz - len(data))} "
                            "bytes are treated as zeros")
        start, end = _align_down(vaddr), _align_up(vaddr + memsz)
        if end > arch.user_limit or end - start > MAX_IMAGE_BYTES:
            raise UnsupportedElf("segment address/size out of supported range")
        run_start = None
        for page in range(start, end + PAGE, PAGE):
            if page < end and page not in mapped_pages:
                mapped_pages.add(page)
                run_start = page if run_start is None else run_start
            elif run_start is not None:
                uc.mem_map(run_start, page - run_start, UC_PROT_ALL)
                run_start = None
        uc.mem_write(vaddr, data[off:off + filesz])
        image_end = max(image_end, end)
        if off <= phoff < off + filesz:
            phdr_addr = vaddr + (phoff - off)
    if sum(1 for _ in mapped_pages) * PAGE > MAX_IMAGE_BYTES:
        raise UnsupportedElf("image too large")

    for seg in loads:   # is the entry point even inside the bytes we were given?
        if seg["p_vaddr"] <= entry < seg["p_vaddr"] + seg["p_filesz"]:
            entry_off = seg["p_offset"] + entry - seg["p_vaddr"]
            if entry_off >= len(data):
                warnings.append(f"the entry point is at file offset {hex(entry_off)} but the file is only "
                                f"{len(data)} bytes: it is truncated and the code it starts with is missing")
    if b"UPX!" in data[:0x200]:
        warnings.append("UPX-packed: the real program is compressed inside; run it through an unpacker "
                        "(AssemblyLine's Extraction services) so the unpacked file is analysed too")

    # ---- stack: strings, then argc/argv/envp/auxv
    stack_top = arch.stack_top
    uc.mem_map(stack_top - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
    sp = stack_top - 0x100

    def push_bytes(b: bytes) -> int:
        nonlocal sp
        sp -= len(b)
        uc.mem_write(sp, b)
        return sp

    argv = argv or ["/tmp/sample"]
    envp = ["PATH=/usr/bin:/bin", "HOME=/root", "SHELL=/bin/sh"]
    argv_ptrs = [push_bytes(a.encode("latin-1") + b"\0") for a in argv]
    env_ptrs = [push_bytes(e.encode("latin-1") + b"\0") for e in envp]
    rand_ptr = push_bytes(bytes(range(16)))
    auxv = [(AT_PAGESZ, PAGE), (AT_ENTRY, entry), (AT_UID, 0), (AT_EUID, 0), (AT_GID, 0),
            (AT_EGID, 0), (AT_RANDOM, rand_ptr)]
    if phdr_addr is not None:
        auxv += [(AT_PHDR, phdr_addr), (AT_PHENT, 32), (AT_PHNUM, phnum)]
    auxv.append((AT_NULL, 0))
    words = [len(argv)] + argv_ptrs + [0] + env_ptrs + [0] + [w for kv in auxv for w in kv]
    sp = (sp - 4 * len(words)) & ~0xF
    uc.mem_write(sp, struct.pack(f"<{len(words)}I", *words))
    uc.reg_write(arch.sp_reg, sp)
    for reg, value in arch.entry_regs.items():   # e.g. MIPS: $t9 = entry, as PIC-aware startup code expects
        uc.reg_write(reg, entry if value == "entry" else value)

    kernel = FakeKernel(uc, arch, brk_base=image_end, stack_low=stack_top - STACK_SIZE,
                        max_syscalls=max_syscalls, relay=relay)
    report = EmulationReport(arch=arch.name, entry=entry, warnings=warnings)
    fault: dict = {}

    def on_interrupt(uc_, intno, _user):
        if intno == arch.intr_no:
            kernel.handle()
        else:
            fault["error"] = {"type": f"unhandled interrupt {intno}",
                              "pc": hex(uc_.reg_read(arch.pc_reg))}
            kernel._stop("interrupt")

    uc.hook_add(UC_HOOK_INTR, on_interrupt)

    # ---- run. Each emu_start segment ends on exit, execve, a limit, or a fork rewind.
    deadline = started + timeout_s
    pc = entry
    while True:
        if kernel.resume is not None:  # rewind to the parent of a finished/abandoned fork
            record, kernel.resume = kernel.resume, None
            pc = kernel.rewind(record)
        remaining_us = int((deadline - time.monotonic()) * 1_000_000)
        if remaining_us <= 0:
            report.stop_reason = "timeout"
            break
        try:
            uc.emu_start(pc, 0, timeout=remaining_us, count=max_instructions)
        except UcError as e:
            report.error = _describe_fault(uc, arch, e)
            report.stop_reason = "fault"
            break
        if kernel.resume is not None:
            continue
        if kernel.stop_reason:
            report.stop_reason = kernel.stop_reason
            break
        if time.monotonic() >= deadline:
            report.stop_reason = "timeout"
            break
        if kernel.has_pending_forks:
            kernel.abandon_path("instruction budget exhausted")
            pc = uc.reg_read(arch.pc_reg)
            continue
        report.stop_reason = "instruction_limit"
        break

    if fault.get("error") and report.error is None:
        report.error = fault["error"]

    report.events = kernel.events
    report.events_dropped = kernel.events_dropped
    report.network = kernel.network
    report.files = {p: bytes(b) for p, b in kernel.files.items()}
    report.file_modes = dict(kernel.file_modes)
    report.stdout = bytes(kernel.stdout)
    report.sent = kernel.sent
    report.received = kernel.received
    if relay is not None:
        relay.close_all()
    report.syscall_counts = dict(kernel.counts)
    report.unknown_syscalls = dict(kernel.unknown_syscalls)
    report.syscalls_total = kernel.syscall_count
    report.open_counts = dict(kernel.open_counts.most_common(20))
    report.elapsed = time.monotonic() - started
    return report
