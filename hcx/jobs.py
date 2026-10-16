"""Job management: run attacks, build a sequential queue, resume sessions,
and keep a searchable history. Every original hashcat flag is preserved;
hcx only injects managed defaults (session, restore path, outfile, potfile,
status stream) when the user did not already supply them.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional, Tuple

from . import util
from .config import Config
from .runner import StatusSnapshot, run
from .store import Store


# --- argument inspection (non-destructive) -------------------------------
def _has_flag(args: List[str], names: Tuple[str, ...]) -> bool:
    for a in args:
        for n in names:
            if a == n or a.startswith(n + "=") or (len(n) == 2 and a.startswith(n) and len(a) > 2):
                return True
    return False


def _value_of(args: List[str], names: Tuple[str, ...]) -> Optional[str]:
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                return args[i + 1]
            if a.startswith(n + "="):
                return a.split("=", 1)[1]
            if len(n) == 2 and a.startswith(n) and len(a) > 2:
                return a[2:]
    return None


def _int_value(args: List[str], names: Tuple[str, ...]) -> Optional[int]:
    v = _value_of(args, names)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


class JobManager:
    def __init__(self, config: Config, store: Store):
        self.cfg = config
        self.store = store
        self.cfg.ensure_dirs()

    # --- building a managed command -------------------------------------
    def _managed_args(self, user_args: List[str], session: str) -> Tuple[List[str], dict]:
        args = list(user_args)
        meta = {}
        sdir = self.cfg.sessions_dir

        if not _has_flag(args, ("--session",)):
            args += ["--session", session]

        if not _has_flag(args, ("--restore-file-path",)):
            restore = sdir / f"{session}.restore"
            args += ["--restore-file-path", str(restore)]
            meta["restore_file"] = str(restore)
        else:
            meta["restore_file"] = _value_of(args, ("--restore-file-path",))

        if not _has_flag(args, ("-o", "--outfile")):
            outfile = sdir / f"{session}.cracked"
            args += ["--outfile", str(outfile)]
            meta["outfile"] = str(outfile)
        else:
            meta["outfile"] = _value_of(args, ("-o", "--outfile"))

        if not _has_flag(args, ("--potfile-path", "--potfile-disable")):
            args += ["--potfile-path", str(self.cfg.potfile_path)]

        if not _has_flag(args, ("--status-json",)):
            timer = str(self.cfg.get("status_timer", 2))
            args += ["--status", "--status-json", "--status-timer", timer]

        return args, meta

    # --- run a single attack --------------------------------------------
    def run_attack(
        self,
        user_args: List[str],
        name: Optional[str] = None,
        queued: bool = False,
    ) -> int:
        binary = self.cfg.require_hashcat()
        mode = _int_value(user_args, ("-m", "--hash-type"))
        attack = _int_value(user_args, ("-a", "--attack-mode"))
        session_req = _value_of(user_args, ("--session",))

        job_id = self.store.create_job(
            name=name or (session_req or "job"),
            session=session_req or "pending",
            mode=mode,
            attack_mode=attack,
            cmd=user_args,
            queued=1 if queued else 0,
            status="queued" if queued else "created",
        )
        session = session_req or f"hcx{job_id}"
        if name is None:
            self.store.update_job(job_id, name=session)

        args, meta = self._managed_args(user_args, session)
        log_file = self.cfg.logs_dir / f"job-{job_id}.log"
        self.store.update_job(
            job_id,
            session=session,
            cmd=args,
            outfile=meta.get("outfile"),
            restore_file=meta.get("restore_file"),
            log_file=str(log_file),
        )

        if queued:
            return job_id  # do not run yet

        return self._execute(job_id, binary, args, log_file)

    def _execute(self, job_id: int, binary: Path, args: List[str], log_file: Path) -> int:
        self.store.update_job(job_id, status="running", started_at=time.time())
        last_write = [0.0]

        def on_status(s: StatusSnapshot) -> None:
            now = time.time()
            if now - last_write[0] < 3:
                return
            last_write[0] = now
            self.store.update_job(
                job_id,
                recovered=s.recovered_count,
                total=s.total_hashes,
                speed=s.speed,
                progress_pct=util.pct(s.done, s.total),
            )

        result = run(binary, args, log_file, on_status=on_status, live=True, echo_raw=True)

        final = result.last
        self.store.update_job(
            job_id,
            status=result.outcome,
            exit_code=result.exit_code,
            ended_at=time.time(),
            queued=0,
            recovered=final.recovered_count if final else None,
            total=final.total_hashes if final else None,
            progress_pct=util.pct(final.done, final.total) if final else None,
        )
        return job_id

    # --- resume ----------------------------------------------------------
    def resume(self, job_id: int) -> int:
        job = self.store.get_job(job_id)
        if not job:
            raise SystemExit(f"no such job: {job_id}")
        binary = self.cfg.require_hashcat()
        session = job["session"]
        args = ["--session", session]
        if job.get("restore_file"):
            args += ["--restore-file-path", job["restore_file"]]
        args += ["--restore", "--status", "--status-json", "--status-timer",
                 str(self.cfg.get("status_timer", 2))]
        log_file = Path(job["log_file"]) if job.get("log_file") else (
            self.cfg.logs_dir / f"job-{job_id}.log")
        return self._execute(job_id, binary, args, log_file)

    # --- queue -----------------------------------------------------------
    def queue_add(self, user_args: List[str], name: Optional[str] = None) -> int:
        return self.run_attack(user_args, name=name, queued=True)

    def queue_run(self, live: bool = True) -> List[int]:
        ran: List[int] = []
        binary = self.cfg.require_hashcat()
        while True:
            job = self.store.next_queued()
            if not job:
                break
            jid = job["id"]
            if live:
                print(util.bold(f"\n=== queue: starting job {jid} ({job['name']}) ==="))
            self._execute(jid, binary, list(job["cmd"]), Path(job["log_file"]))
            ran.append(jid)
        return ran
