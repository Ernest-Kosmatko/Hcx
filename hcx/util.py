"""Small shared helpers: formatting, terminal colour, time/number parsing."""

from __future__ import annotations

import os
import sys
import time
from typing import Optional

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def green(t: str) -> str:
    return _c("32", t)


def yellow(t: str) -> str:
    return _c("33", t)


def red(t: str) -> str:
    return _c("31", t)


def cyan(t: str) -> str:
    return _c("36", t)


def human_count(n: float) -> str:
    """Format a hash/sec count with H/kH/MH/GH units."""
    units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s"]
    v = float(n)
    i = 0
    while v >= 1000 and i < len(units) - 1:
        v /= 1000.0
        i += 1
    return f"{v:,.2f} {units[i]}"


def human_int(n: float) -> str:
    units = ["", "K", "M", "B", "T", "P"]
    v = float(n)
    i = 0
    while v >= 1000 and i < len(units) - 1:
        v /= 1000.0
        i += 1
    if i == 0:
        return f"{int(v):,}"
    return f"{v:,.2f}{units[i]}"


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    parts = []
    for size, label in ((86400, "d"), (3600, "h"), (60, "m"), (1, "s")):
        if seconds >= size:
            parts.append(f"{seconds // size}{label}")
            seconds %= size
    return " ".join(parts[:3])


def fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def pct(done: float, total: float) -> float:
    if not total:
        return 0.0
    return min(100.0, 100.0 * done / total)
