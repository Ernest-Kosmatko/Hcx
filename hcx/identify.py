"""Hash identification.

Two layers:
  * `identify_with_hashcat` delegates to hashcat's own `--identify`, the
    authoritative answer (it knows every mode the installed build supports).
  * `guess` is a fast offline heuristic for when you just want a hint
    without launching hashcat.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from . import runner


class Candidate:
    __slots__ = ("mode", "name", "category")

    def __init__(self, mode: int, name: str, category: str = ""):
        self.mode = mode
        self.name = name
        self.category = category

    def __repr__(self) -> str:
        return f"-m {self.mode:<7} {self.name}"


def identify_with_hashcat(binary: Path, sample: str) -> List[Candidate]:
    """Run `hashcat --identify` on a single hash string."""
    tmp = Path(tempfile.gettempdir()) / "hcx_identify.tmp"
    tmp.write_text(sample.strip() + "\n", encoding="utf-8")
    try:
        cp = runner.capture(binary, ["--identify", str(tmp), "--quiet"], timeout=60)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return _parse_identify(cp.stdout)


def _parse_identify(text: str) -> List[Candidate]:
    out: List[Candidate] = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            continue
        if not re.fullmatch(r"\d+", parts[0]):
            continue
        mode = int(parts[0])
        name = parts[1]
        cat = parts[2] if len(parts) > 2 else ""
        out.append(Candidate(mode, name, cat))
    return out


# --- offline heuristic ---------------------------------------------------
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def _is_hex(s: str, length: Optional[int] = None) -> bool:
    if length is not None and len(s) != length:
        return False
    return bool(_HEX.fullmatch(s))


def guess(sample: str) -> List[Candidate]:
    """Best-effort offline guess. Not exhaustive; use --identify for truth."""
    s = sample.strip()
    c: List[Candidate] = []

    # Prefixed / structured formats first.
    if s.startswith(("$2a$", "$2b$", "$2y$")):
        c.append(Candidate(3200, "bcrypt $2*$", "Operating System"))
    elif s.startswith("$1$"):
        c.append(Candidate(500, "md5crypt $1$", "Operating System"))
    elif s.startswith("$5$"):
        c.append(Candidate(7400, "sha256crypt $5$", "Operating System"))
    elif s.startswith("$6$"):
        c.append(Candidate(1800, "sha512crypt $6$", "Operating System"))
    elif s.startswith("$apr1$"):
        c.append(Candidate(1600, "Apache apr1 md5", "Network Protocol"))
    elif s.startswith(("$P$", "$H$")):
        c.append(Candidate(400, "phpass (WordPress/Joomla)", "Framework"))
    elif s.startswith("{SSHA}"):
        c.append(Candidate(111, "nsldaps/SSHA", "Network Protocol"))
    elif s.startswith("{SHA}"):
        c.append(Candidate(101, "nsldap/SHA", "Network Protocol"))
    elif s.startswith("$pbkdf2-sha256$"):
        c.append(Candidate(10900, "PBKDF2-HMAC-SHA256", "Generic KDF"))
    elif s.startswith("$argon2"):
        c.append(Candidate(34000, "argon2 (if supported)", "Generic KDF"))
    elif s.startswith("sha1$") or s.startswith("pbkdf2_sha256$"):
        c.append(Candidate(10000, "Django PBKDF2-SHA256", "Framework"))

    # NetNTLM / Kerberos style (contain specific markers).
    if "$krb5tgs$23$" in s:
        c.append(Candidate(13100, "Kerberos TGS-REP (RC4)", "Network Protocol"))
    if "$krb5asrep$23$" in s:
        c.append(Candidate(18200, "Kerberos AS-REP (RC4)", "Network Protocol"))
    if re.search(r"::.*:.*:.*:", s) and _looks_netntlm(s):
        c.append(Candidate(5600, "NetNTLMv2", "Network Protocol"))

    # Raw hex digests by length.
    if _is_hex(s):
        n = len(s)
        if n == 32:
            c.append(Candidate(0, "MD5", "Raw Hash"))
            c.append(Candidate(1000, "NTLM", "Operating System"))
        elif n == 40:
            c.append(Candidate(100, "SHA1", "Raw Hash"))
        elif n == 56:
            c.append(Candidate(1300, "SHA2-224", "Raw Hash"))
        elif n == 64:
            c.append(Candidate(1400, "SHA2-256", "Raw Hash"))
        elif n == 96:
            c.append(Candidate(10800, "SHA2-384", "Raw Hash"))
        elif n == 128:
            c.append(Candidate(1700, "SHA2-512", "Raw Hash"))
        elif n == 16:
            c.append(Candidate(190, "SHA1(half) / misc", "Raw Hash"))

    return c


def _looks_netntlm(s: str) -> bool:
    return s.count(":") >= 4 and len(s) > 50
