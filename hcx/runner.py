"""Execution engine: launches hashcat, mirrors its output, and parses the
machine-readable status stream into a compact live dashboard.

hashcat is run as a child process. Its complete output is always written
verbatim to a per-job log file, so nothing it prints is ever lost. When
the JSON status stream is enabled, hcx also renders a tidy one-line
dashboard and records progress into the job store.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import util


class StatusSnapshot:
    """Normalised view of a hashcat --status-json object."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.progress = raw.get("progress", [0, 0])
        devs = raw.get("devices", []) or []
        self.speed = sum(d.get("speed", 0) for d in devs)
        self.recovered = (raw.get("recovered_hashes") or [0, 0])
        self.status = raw.get("status")  # numeric status code
        self.time_start = raw.get("time_start")
        self.estimated_stop = raw.get("estimated_stop")
        self.target = raw.get("target")

    @property
    def done(self) -> int:
        return self.progress[0] if self.progress else 0

    @property
    def total(self) -> int:
        return self.progress[1] if len(self.progress) > 1 else 0

    @property
    def recovered_count(self) -> int:
        return self.recovered[0] if self.recovered else 0

    @property
    def total_hashes(self) -> int:
        return self.recovered[1] if len(self.recovered) > 1 else 0

    @property
    def eta_seconds(self) -> float:
        if self.estimated_stop:
            return max(0.0, self.estimated_stop - time.time())
        if self.speed and self.total:
            return max(0.0, (self.total - self.done) / self.speed)
        return 0.0


# hashcat exit codes (from its docs). Used for human-readable outcomes.
EXIT_MEANING = {
    0: "cracked",
    1: "exhausted",
    2: "aborted",
    3: "aborted-checkpoint",
    4: "aborted-runtime",
    -1: "error",
    -2: "gpu-watchdog",
}


class RunResult:
    def __init__(self, exit_code: int, last: Optional[StatusSnapshot], log_file: Path):
        self.exit_code = exit_code
        self.last = last
        self.log_file = log_file

    @property
    def outcome(self) -> str:
        return EXIT_MEANING.get(self.exit_code, f"exit {self.exit_code}")


def run(
    binary: Path,
    args: List[str],
    log_file: Path,
    on_status: Optional[Callable[[StatusSnapshot], None]] = None,
    live: bool = True,
    echo_raw: bool = False,
) -> RunResult:
    """Run hashcat and stream its output.

    args: full argument list passed straight to hashcat (unaltered).
    on_status: optional callback invoked for every status snapshot.
    live: render the compact dashboard to stderr.
    echo_raw: also echo raw hashcat stdout lines (useful without status json).
    """
    cmd = [str(binary), *args]
    log_file.parent.mkdir(parents=True, exist_ok=True)

    last: Optional[StatusSnapshot] = None
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(Path(binary).parent),  # hashcat resolves OpenCL/ etc. from here
    )

    with log_file.open("w", encoding="utf-8", errors="replace") as log:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                log.write(line)
                stripped = line.strip()
                snap = _parse_status_line(stripped)
                if snap is not None:
                    last = snap
                    if on_status:
                        on_status(snap)
                    if live:
                        _render_dashboard(snap)
                    continue
                if echo_raw and stripped:
                    sys.stdout.write(line)
                    sys.stdout.flush()
        except KeyboardInterrupt:
            # Forward a gentle stop so hashcat writes its restore checkpoint.
            _interrupt(proc)
        finally:
            proc.wait()
            if live:
                sys.stderr.write("\n")
                sys.stderr.flush()

    return RunResult(_signed(proc.returncode), last, log_file)


def _signed(code: Optional[int]) -> int:
    """Normalise Windows unsigned exit codes to signed ints."""
    if code is None:
        return -1
    if code >= 0x80000000:
        return code - 0x100000000
    return code


def _parse_status_line(line: str) -> Optional[StatusSnapshot]:
    if not line.startswith("{") or '"status"' not in line:
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict) or "progress" not in obj:
        return None
    return StatusSnapshot(obj)


def _render_dashboard(s: StatusSnapshot) -> None:
    bar = _progress_bar(util.pct(s.done, s.total))
    line = (
        f"\r{util.cyan(bar)} {util.pct(s.done, s.total):5.1f}%  "
        f"{util.green(str(s.recovered_count))}/{s.total_hashes} cracked  "
        f"{util.bold(util.human_count(s.speed))}  "
        f"ETA {util.yellow(util.human_duration(s.eta_seconds))}   "
    )
    sys.stderr.write(line)
    sys.stderr.flush()


def _progress_bar(percent: float, width: int = 24) -> str:
    filled = int(round(width * percent / 100.0))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _interrupt(proc: subprocess.Popen) -> None:
    try:
        if sys.platform == "win32":
            proc.terminate()
        else:
            import signal

            proc.send_signal(signal.SIGINT)
    except Exception:
        proc.terminate()


def capture(binary: Path, args: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run hashcat and capture all output (no live dashboard)."""
    return subprocess.run(
        [str(binary), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=str(Path(binary).parent),  # hashcat resolves OpenCL/ etc. from here
    )
