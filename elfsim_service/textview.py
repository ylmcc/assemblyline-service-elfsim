"""Render raw bytes as text a human can read (no hex dumps)."""
from __future__ import annotations

import re

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
    return runs[:limit]
