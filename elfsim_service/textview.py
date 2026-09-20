"""Render raw bytes as text a human can read (no hex dumps)."""
from __future__ import annotations

import re
from collections import Counter

_ESCAPES = {0x5C: "\\\\", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}


def readable(data: bytes, limit: int = 200) -> str:
    """Printable ASCII as itself; everything else as a short escape (\\x00, \\n, \\\\...).

    ``b"\\x04px86"`` -> ``\\x04px86``. Truncated output ends with the number of bytes left out.
    """
    out = []
    for b in data[:limit]:
        if b in _ESCAPES:
            out.append(_ESCAPES[b])
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    text = "".join(out)
    if len(data) > limit:
        text += f" ... (+{len(data) - limit} more bytes)"
    return text


def text_runs(data: bytes, min_len: int = 3, limit: int = 12) -> list:
    """Runs of printable ASCII (like ``strings``), e.g. the ids/names inside a binary protocol."""
    runs = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    return list(dict.fromkeys(runs))[:limit]          # first occurrence order, no repeats


_ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(data: bytes) -> bytes:
    """Remove terminal colour/cursor escape sequences (\\x1b[1;31m ...) for display."""
    return _ANSI.sub(b"", data)


def printable_ratio(data: bytes) -> float:
    """Share of bytes that are printable ASCII or ordinary whitespace (\\r \\n \\t)."""
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)


def line_summary(data: bytes, limit: int = 12):
    """For a text conversation (login attempts, commands...): (total lines, distinct lines,
    [(line, count)...]) with the most frequent first. None if there are no lines."""
    lines = [l for l in data.replace(b"\r\n", b"\n").split(b"\n") if l.strip()]
    if not lines:
        return None
    counts = Counter(lines)
    top = [(readable(line, 120), n) for line, n in counts.most_common(limit)]
    return len(lines), len(counts), top
