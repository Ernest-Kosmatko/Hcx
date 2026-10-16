"""Reporting: parse cracked output (potfile / per-job outfile), compute
statistics, and export results to CSV, JSON or a self-contained HTML page.
"""

from __future__ import annotations

import csv
import html
import io
import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import util
from .store import Store


class Cracked:
    __slots__ = ("hash", "plain", "raw")

    def __init__(self, h: str, plain: str, raw: str):
        self.hash = h
        self.plain = plain
        self.raw = raw

    def as_dict(self) -> dict:
        return {"hash": self.hash, "plain": self.plain}


def parse_cracked_file(path: Path) -> List[Cracked]:
    """Parse a hashcat potfile or outfile (default `hash:plain` layout).

    Split is performed on the first ':' — correct for unsalted hashes
    (NTLM, MD5, SHA1, ...). The full raw line is always retained so
    salted layouts remain recoverable downstream.
    """
    out: List[Cracked] = []
    if not path or not Path(path).is_file():
        return out
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if ":" in line:
                h, plain = line.split(":", 1)
            else:
                h, plain = line, ""
            out.append(Cracked(h, plain, line))
    return out


def dedup(records: Iterable[Cracked]) -> List[Cracked]:
    seen = set()
    out = []
    for r in records:
        key = r.raw
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


# --- statistics ----------------------------------------------------------
def password_insights(records: List[Cracked]) -> Dict[str, object]:
    """Lightweight analysis of recovered plaintext for a findings report."""
    plains = [r.plain for r in records if r.plain]
    total = len(plains)
    if total == 0:
        return {"total": 0}
    lengths: Dict[int, int] = {}
    classes = {"lower": 0, "upper": 0, "digit": 0, "symbol": 0, "mixed": 0}
    for p in plains:
        lengths[len(p)] = lengths.get(len(p), 0) + 1
        kinds = set()
        for ch in p:
            if ch.islower():
                kinds.add("lower")
            elif ch.isupper():
                kinds.add("upper")
            elif ch.isdigit():
                kinds.add("digit")
            else:
                kinds.add("symbol")
        if len(kinds) == 1:
            classes[next(iter(kinds))] += 1
        else:
            classes["mixed"] += 1
    freq: Dict[str, int] = {}
    for p in plains:
        freq[p] = freq.get(p, 0) + 1
    top = sorted(freq.items(), key=lambda kv: kv[1], reverse=True)[:10]
    avg_len = sum(len(p) for p in plains) / total
    return {
        "total": total,
        "avg_length": round(avg_len, 2),
        "min_length": min(len(p) for p in plains),
        "max_length": max(len(p) for p in plains),
        "length_histogram": dict(sorted(lengths.items())),
        "char_classes": classes,
        "top_passwords": top,
    }


def job_summary(store: Store) -> Dict[str, object]:
    jobs = store.list_jobs(limit=10_000)
    recovered = sum((j.get("recovered") or 0) for j in jobs)
    total = sum((j.get("total") or 0) for j in jobs)
    by_status: Dict[str, int] = {}
    for j in jobs:
        by_status[j["status"]] = by_status.get(j["status"], 0) + 1
    return {
        "jobs": len(jobs),
        "recovered": recovered,
        "total_hashes": total,
        "crack_rate": round(util.pct(recovered, total), 2),
        "by_status": by_status,
    }


# --- export --------------------------------------------------------------
def export(records: List[Cracked], fmt: str, out_path: Optional[Path]) -> str:
    fmt = fmt.lower()
    if fmt == "csv":
        text = _to_csv(records)
    elif fmt == "json":
        text = json.dumps([r.as_dict() for r in records], indent=2, ensure_ascii=False)
    elif fmt == "html":
        text = _to_html(records)
    else:
        raise SystemExit(f"unknown export format: {fmt} (use csv|json|html)")
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    return text


def _to_csv(records: List[Cracked]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["hash", "plain"])
    for r in records:
        w.writerow([r.hash, r.plain])
    return buf.getvalue()


def _to_html(records: List[Cracked]) -> str:
    insights = password_insights(records)
    rows = "\n".join(
        f"<tr><td class='h'>{html.escape(r.hash)}</td>"
        f"<td class='p'>{html.escape(r.plain)}</td></tr>"
        for r in records
    )
    top = insights.get("top_passwords", []) or []
    top_rows = "\n".join(
        f"<tr><td>{html.escape(str(p))}</td><td>{c}</td></tr>" for p, c in top
    )
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hcx report</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: system-ui, sans-serif; margin: 2rem; background:#0f1115; color:#e7e9ee; }}
 @media (prefers-color-scheme: light) {{ body {{ background:#fff; color:#111; }} }}
 h1 {{ font-size:1.4rem; }}
 .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin:1rem 0; }}
 .card {{ border:1px solid #3a3f4b; border-radius:10px; padding:1rem 1.25rem; min-width:150px; }}
 .card b {{ display:block; font-size:1.6rem; }}
 table {{ border-collapse:collapse; width:100%; margin-top:1rem; font-size:.9rem; }}
 th,td {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid #2a2e37; }}
 td.h {{ font-family:ui-monospace,monospace; color:#9aa4b2; word-break:break-all; }}
 td.p {{ font-family:ui-monospace,monospace; color:#8fe08f; }}
 .muted {{ color:#8a93a3; font-size:.85rem; }}
</style></head><body>
<h1>hcx &mdash; recovered credentials report</h1>
<p class="muted">Generated {generated} &middot; {len(records)} entries</p>
<div class="cards">
 <div class="card"><b>{insights.get('total', 0)}</b>recovered</div>
 <div class="card"><b>{insights.get('avg_length', 0)}</b>avg length</div>
 <div class="card"><b>{insights.get('max_length', 0)}</b>max length</div>
</div>
<h2>Top passwords</h2>
<table><tr><th>password</th><th>count</th></tr>{top_rows}</table>
<h2>All results</h2>
<table><tr><th>hash</th><th>plain</th></tr>{rows}</table>
</body></html>"""
