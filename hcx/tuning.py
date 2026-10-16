"""Tuning helpers: benchmarking, device inventory, keyspace/ETA estimation
and workload advice. All benchmarks are run by the real hashcat binary and
their results are stored so ETA estimates can reuse them later.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import runner, util
from .store import Store

_SPEED_RE = re.compile(r"Speed\.#\d+[.\s]*:\s*([\d.]+)\s*([kMGTP]?)H/s", re.I)
_MODE_RE = re.compile(r"Hash\.?mode.*?:\s*(\d+)", re.I)
_UNIT = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12, "p": 1e15}

# Charset cardinalities for hashcat built-in mask tokens.
_CHARSET = {"l": 26, "u": 26, "d": 10, "s": 33, "a": 95, "b": 256, "h": 16, "H": 16}


def parse_speed(text: str) -> float:
    """Sum per-device Speed.#N lines into total H/s."""
    total = 0.0
    for m in _SPEED_RE.finditer(text):
        total += float(m.group(1)) * _UNIT[m.group(2).lower()]
    return total


def benchmark(binary: Path, store: Optional[Store], mode: Optional[int] = None) -> List[Tuple[int, float]]:
    """Run `hashcat -b`, optionally for a single mode. Returns (mode, speed)."""
    args = ["-b"]
    if mode is not None:
        args += ["-m", str(mode)]
    cp = runner.capture(binary, args, timeout=3600)
    results = _parse_benchmark(cp.stdout)
    if store:
        for mode_n, speed in results:
            store.add_benchmark(mode_n, "", speed, "")
    return results


def _parse_benchmark(text: str) -> List[Tuple[int, float]]:
    results: List[Tuple[int, float]] = []
    cur_mode: Optional[int] = None
    speeds: List[float] = []
    for line in text.splitlines():
        mm = _MODE_RE.search(line)
        if mm:
            if cur_mode is not None and speeds:
                results.append((cur_mode, sum(speeds)))
            cur_mode = int(mm.group(1))
            speeds = []
            continue
        sm = _SPEED_RE.search(line)
        if sm:
            speeds.append(float(sm.group(1)) * _UNIT[sm.group(2).lower()])
    if cur_mode is not None and speeds:
        results.append((cur_mode, sum(speeds)))
    return results


def devices(binary: Path) -> str:
    """Return hashcat's backend device inventory (`hashcat -I`)."""
    cp = runner.capture(binary, ["-I"], timeout=120)
    return cp.stdout


def mask_keyspace(mask: str) -> Optional[int]:
    """Compute the number of candidates for a mask built from built-in sets.

    Returns None if the mask references custom charsets (-1..-4), whose
    size hcx cannot know without the full command.
    """
    total = 1
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            tok = mask[i + 1]
            if tok in _CHARSET:
                total *= _CHARSET[tok]
            elif tok in "1234":
                return None  # custom charset, size unknown here
            elif tok == "?":
                total *= 1  # literal '?'
            i += 2
            continue
        total *= 1  # literal character
        i += 1
    return total


def eta(keyspace: float, speed: float) -> float:
    if speed <= 0:
        return float("inf")
    return keyspace / speed


def workload_advice(slow_hash: bool) -> List[str]:
    """Human advice; nothing is enforced, these are just suggestions."""
    tips = [
        "-w 3            balanced workload (default sweet spot for most GPUs)",
        "-w 4            maximum workload; best raw speed, less responsive desktop",
        "-O              optimized kernels: much faster but limits password length",
        "-I              list backend devices to confirm the GPU is in use",
        "-d <id>         pin the attack to specific device id(s)",
    ]
    if slow_hash:
        tips += [
            "-S              slow-candidate mode, helps some slow/compute-bound hashes",
            "--spin-damp 0   let the device run flat out (watch temperatures)",
            "tip: slow hashes (bcrypt, *crypt, PBKDF2) are rule/wordlist bound; "
            "invest in good wordlists and targeted rules over huge masks",
        ]
    else:
        tips += [
            "tip: fast hashes (MD5/NTLM/SHA1) are keyspace bound; mask and "
            "brute-force attacks scale well here",
        ]
    return tips


# Rough heuristic: hashcat modes that are deliberately slow (KDF/crypt).
_SLOW_MODES = {
    400, 500, 1600, 1800, 3200, 7400, 7401, 9000, 9100, 10000, 10900,
    11300, 11600, 12500, 13000, 13100, 13400, 13721, 13722, 13723, 14600,
    15700, 16900, 18200, 22000, 34000,
}


def is_slow_mode(mode: Optional[int]) -> bool:
    return mode in _SLOW_MODES if mode is not None else False
