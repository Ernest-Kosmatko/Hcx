"""Command-line interface for hcx.

Design rule: hcx never hides or rewrites hashcat's own interface. The
`run`/`queue add` commands forward their arguments to hashcat verbatim;
everything else is additive tooling layered on top.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, identify, planner, report, tuning, util
from .config import Config
from .jobs import JobManager
from .store import Store

PROG = "hcx"


# --- small output helpers ------------------------------------------------
def _table(rows: List[list], headers: List[str]) -> str:
    cols = len(headers)
    widths = [len(h) for h in headers]
    srows = []
    for r in rows:
        sr = [("" if c is None else str(c)) for c in r]
        srows.append(sr)
        for i in range(cols):
            widths[i] = max(widths[i], len(sr[i]))
    line = "  ".join(util.bold(h.ljust(widths[i])) for i, h in enumerate(headers))
    out = [line]
    for sr in srows:
        out.append("  ".join(sr[i].ljust(widths[i]) for i in range(cols)))
    return "\n".join(out)


def _split_passthrough(rest: List[str]):
    name: Optional[str] = None
    r = list(rest)
    while r and r[0] in ("--name", "-n"):
        if len(r) < 2:
            raise SystemExit(f"{r[0]} needs a value")
        name = r[1]
        r = r[2:]
    if r and r[0] == "--":
        r = r[1:]
    if not r:
        raise SystemExit("no hashcat arguments given (usage: hcx run [--name N] -- <hashcat args>)")
    return name, r


# --- context -------------------------------------------------------------
class Ctx:
    def __init__(self, args: argparse.Namespace):
        self.cfg = Config(Path(args.home) if getattr(args, "home", None) else None)
        self.store = Store(self.cfg.db_path)
        self.jobs = JobManager(self.cfg, self.store)

    def close(self):
        self.store.close()


# --- command handlers ----------------------------------------------------
def cmd_run(ctx: Ctx, rest: List[str]) -> int:
    name, args = _split_passthrough(rest)
    jid = ctx.jobs.run_attack(args, name=name)
    job = ctx.store.get_job(jid)
    print(util.bold(f"\njob {jid} [{job['status']}]") +
          f"  recovered {job.get('recovered')}/{job.get('total')}"
          f"  log: {job.get('log_file')}")
    return 0 if (job and job.get("exit_code") in (0, 1)) else 0


def cmd_queue(ctx: Ctx, rest: List[str]) -> int:
    if not rest:
        raise SystemExit("usage: hcx queue <add|list|run|clear>")
    sub, rest = rest[0], rest[1:]
    if sub == "add":
        name, args = _split_passthrough(rest)
        jid = ctx.jobs.queue_add(args, name=name)
        print(f"queued job {jid}")
    elif sub == "list":
        rows = [[j["id"], j["name"], j["status"], _mode(j)] for j in ctx.store.list_jobs(queued=True)]
        print(_table(rows, ["id", "name", "status", "mode"]) if rows else "queue empty")
    elif sub == "run":
        ran = ctx.jobs.queue_run()
        print(util.green(f"\nqueue finished: {len(ran)} job(s) run"))
    elif sub == "clear":
        for j in ctx.store.list_jobs(queued=True):
            if j["status"] in ("queued", "created"):
                ctx.store.delete_job(j["id"])
        print("queue cleared")
    else:
        raise SystemExit(f"unknown queue subcommand: {sub}")
    return 0


def cmd_jobs(ctx: Ctx, args) -> int:
    rows = []
    for j in ctx.store.list_jobs(limit=args.limit):
        rows.append([
            j["id"], j["name"], j["status"], _mode(j),
            f"{j.get('recovered') or 0}/{j.get('total') or 0}",
            f"{(j.get('progress_pct') or 0):.0f}%",
            util.fmt_ts(j.get("created_at")),
        ])
    print(_table(rows, ["id", "name", "status", "mode", "cracked", "prog", "created"])
          if rows else "no jobs yet")
    return 0


def cmd_show(ctx: Ctx, args) -> int:
    j = ctx.store.get_job(args.id)
    if not j:
        raise SystemExit(f"no such job: {args.id}")
    print(util.bold(f"job {j['id']}  {j['name']}"))
    for k in ("status", "session", "mode", "attack_mode", "exit_code",
              "recovered", "total", "progress_pct", "speed"):
        print(f"  {k:<13} {j.get(k)}")
    print(f"  {'created':<13} {util.fmt_ts(j.get('created_at'))}")
    print(f"  {'started':<13} {util.fmt_ts(j.get('started_at'))}")
    print(f"  {'ended':<13} {util.fmt_ts(j.get('ended_at'))}")
    print(f"  {'outfile':<13} {j.get('outfile')}")
    print(f"  {'restore':<13} {j.get('restore_file')}")
    print(f"  {'log':<13} {j.get('log_file')}")
    print(f"  {'command':<13} hashcat {' '.join(j.get('cmd') or [])}")
    return 0


def cmd_resume(ctx: Ctx, args) -> int:
    jid = ctx.jobs.resume(args.id)
    j = ctx.store.get_job(jid)
    print(util.bold(f"\njob {jid} [{j['status']}]  recovered {j.get('recovered')}/{j.get('total')}"))
    return 0


def cmd_rm(ctx: Ctx, args) -> int:
    for jid in args.ids:
        ctx.store.delete_job(jid)
    print(f"removed {len(args.ids)} job(s)")
    return 0


def cmd_report(ctx: Ctx, args) -> int:
    if args.what == "summary":
        print(json.dumps(report.job_summary(ctx.store), indent=2))
        return 0
    if args.what == "potfile":
        recs = report.dedup(report.parse_cracked_file(ctx.cfg.potfile_path))
        _print_cracked(recs)
        return 0
    if args.what == "job":
        if args.id is None:
            raise SystemExit("usage: hcx report job <id>")
        j = ctx.store.get_job(args.id)
        if not j:
            raise SystemExit(f"no such job: {args.id}")
        recs = report.parse_cracked_file(Path(j["outfile"])) if j.get("outfile") else []
        _print_cracked(recs)
        return 0
    if args.what == "export":
        recs = _collect_for_export(ctx, args.source)
        text = report.export(recs, args.format, Path(args.out) if args.out else None)
        if args.out:
            print(f"wrote {len(recs)} records to {args.out}")
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return 0
    raise SystemExit("usage: hcx report <summary|potfile|job|export>")


def _collect_for_export(ctx: Ctx, source: str):
    if source in ("pot", "potfile"):
        return report.dedup(report.parse_cracked_file(ctx.cfg.potfile_path))
    try:
        jid = int(source)
    except ValueError:
        raise SystemExit("export source must be 'potfile' or a job id")
    j = ctx.store.get_job(jid)
    if not j or not j.get("outfile"):
        raise SystemExit(f"job {source} has no outfile")
    return report.parse_cracked_file(Path(j["outfile"]))


def _print_cracked(recs) -> None:
    if not recs:
        print("nothing cracked yet")
        return
    for r in recs:
        print(f"{util.dim(r.hash)}  {util.green(r.plain)}")
    ins = report.password_insights(recs)
    print(util.bold(f"\n{ins['total']} cracked")
          + f"  avg len {ins.get('avg_length')}  "
          + f"range {ins.get('min_length')}-{ins.get('max_length')}")


def cmd_plan(ctx: Ctx, args) -> int:
    steps = planner.build_plan(
        hashfile=args.hashfile,
        mode=args.mode,
        wordlists=args.wordlist,
        rules=args.rule,
        masks=args.mask,
        profile=args.profile,
        max_mask_len=args.max_mask_len,
    )
    print(util.bold(f"plan ({args.profile}, {len(steps)} steps):"))
    print(planner.describe(steps))
    if args.queue or args.run:
        for s in steps:
            ctx.jobs.queue_add(s.args, name=s.name)
        print(util.cyan(f"\nqueued {len(steps)} steps"))
        if args.run:
            ran = ctx.jobs.queue_run()
            print(util.green(f"queue finished: {len(ran)} job(s) run"))
    return 0


def cmd_mask(ctx: Ctx, args) -> int:
    masks = planner.mask_series(args.charset, args.min, args.max)
    for m in masks:
        ks = tuning.mask_keyspace(m)
        ks_s = util.human_int(ks) if ks is not None else "?"
        print(f"{m:<24} keyspace {ks_s}")
    return 0


def cmd_identify(ctx: Ctx, args) -> int:
    sample = args.sample
    cands = []
    if not args.offline:
        binary = ctx.cfg.hashcat_binary()
        if binary:
            try:
                cands = identify.identify_with_hashcat(binary, sample)
            except Exception as e:  # fall back to heuristic
                print(util.dim(f"(hashcat --identify unavailable: {e}; using heuristic)"))
    if not cands:
        cands = identify.guess(sample)
    if not cands:
        print("no candidates found")
        return 0
    rows = [[c.mode, c.name, c.category] for c in cands]
    print(_table(rows, ["mode", "name", "category"]))
    print(util.dim("\nrun with:  hcx run -- -m <mode> -a 0 <hashfile> <wordlist>"))
    return 0


def cmd_benchmark(ctx: Ctx, args) -> int:
    binary = ctx.cfg.require_hashcat()
    print(util.dim("running hashcat benchmark (this can take a while)..."))
    results = tuning.benchmark(binary, ctx.store, mode=args.mode)
    rows = [[m, util.human_count(s), "slow" if tuning.is_slow_mode(m) else "fast"]
            for m, s in results]
    print(_table(rows, ["mode", "speed", "class"]) if rows else "no benchmark data parsed")
    return 0


def cmd_devices(ctx: Ctx, args) -> int:
    binary = ctx.cfg.require_hashcat()
    sys.stdout.write(tuning.devices(binary))
    return 0


def cmd_eta(ctx: Ctx, args) -> int:
    if args.mask:
        ks = tuning.mask_keyspace(args.mask)
        if ks is None:
            raise SystemExit("cannot compute keyspace for a mask with custom charsets")
    elif args.keyspace is not None:
        ks = args.keyspace
    else:
        raise SystemExit("provide --mask or --keyspace")

    speed = args.speed
    if speed is None and args.mode is not None:
        bm = ctx.store.latest_benchmark(args.mode)
        if bm:
            speed = bm["speed"]
            print(util.dim(f"using stored benchmark for -m {args.mode}: {util.human_count(speed)}"))
    if speed is None:
        raise SystemExit("provide --speed, or --mode with a stored benchmark (run: hcx benchmark -m <mode>)")

    secs = tuning.eta(ks, speed)
    print(f"keyspace {util.human_int(ks)}  @ {util.human_count(speed)}  ->  ETA {util.yellow(util.human_duration(secs))}")
    return 0


def cmd_config(ctx: Ctx, args) -> int:
    if args.action == "show":
        print(json.dumps(ctx.cfg.as_dict(), indent=2))
    elif args.action == "set-hashcat":
        p = Path(args.value).expanduser()
        if not p.is_file():
            raise SystemExit(f"not a file: {p}")
        ctx.cfg.set("hashcat", str(p))
        print(f"hashcat set to {p}")
    elif args.action == "set":
        if not args.value or "=" not in args.value:
            raise SystemExit("usage: hcx config set KEY=VALUE")
        k, v = args.value.split("=", 1)
        ctx.cfg.set(k.strip(), v.strip())
        print(f"{k.strip()} = {v.strip()}")
    return 0


def _mode(j) -> str:
    m = j.get("mode")
    a = j.get("attack_mode")
    return f"-m {m} -a {a}" if m is not None else "-"


# --- parser --------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Orchestration layer for hashcat (jobs, reports, planning, tuning).",
    )
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    p.add_argument("--home", help="override hcx state directory")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("run", add_help=False,
                   help="run an attack; args after -- go straight to hashcat")
    sub.add_parser("queue", add_help=False,
                   help="manage a sequential attack queue (add/list/run/clear)")

    pj = sub.add_parser("jobs", help="list job history")
    pj.add_argument("--limit", type=int, default=30)

    ps = sub.add_parser("show", help="show a job's details")
    ps.add_argument("id", type=int)

    pr = sub.add_parser("resume", help="resume a job via hashcat --restore")
    pr.add_argument("id", type=int)

    prm = sub.add_parser("rm", help="remove job(s) from history")
    prm.add_argument("ids", type=int, nargs="+")

    prep = sub.add_parser("report", help="summaries and exports of cracked results")
    prep.add_argument("what", choices=["summary", "potfile", "job", "export"])
    prep.add_argument("id", type=int, nargs="?")
    prep.add_argument("--source", default="potfile", help="export source: 'potfile' or a job id")
    prep.add_argument("--format", default="csv", choices=["csv", "json", "html"])
    prep.add_argument("--out", help="write export to this file")

    pp = sub.add_parser("plan", help="build (and optionally queue/run) an attack plan")
    pp.add_argument("--hashfile", required=True)
    pp.add_argument("--mode", type=int, required=True)
    pp.add_argument("--wordlist", action="append", default=[])
    pp.add_argument("--rule", action="append", default=[])
    pp.add_argument("--mask", action="append", default=[])
    pp.add_argument("--profile", choices=["quick", "standard", "thorough"], default="standard")
    pp.add_argument("--max-mask-len", type=int, default=8, dest="max_mask_len")
    pp.add_argument("--queue", action="store_true", help="append steps to the queue")
    pp.add_argument("--run", action="store_true", help="queue then run immediately")

    pm = sub.add_parser("mask", help="generate a mask series with keyspace sizes")
    pm.add_argument("--charset", default="?a")
    pm.add_argument("--min", type=int, default=1)
    pm.add_argument("--max", type=int, default=8)

    pi = sub.add_parser("identify", help="identify a hash (hashcat --identify + heuristic)")
    pi.add_argument("sample")
    pi.add_argument("--offline", action="store_true", help="skip hashcat, heuristic only")

    pb = sub.add_parser("benchmark", help="run and store hashcat benchmarks")
    pb.add_argument("--mode", type=int, help="benchmark a single hash mode")

    sub.add_parser("devices", help="list backend devices (hashcat -I)")

    pe = sub.add_parser("eta", help="estimate time for a keyspace/mask at a given speed")
    pe.add_argument("--mask")
    pe.add_argument("--keyspace", type=float)
    pe.add_argument("--speed", type=float, help="H/s (defaults to stored benchmark for --mode)")
    pe.add_argument("--mode", type=int)

    pc = sub.add_parser("config", help="show or change configuration")
    pc.add_argument("action", choices=["show", "set-hashcat", "set"])
    pc.add_argument("value", nargs="?")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        build_parser().print_help()
        return 0

    # Passthrough commands are parsed manually so hashcat flags survive intact.
    if argv[0] in ("run", "queue"):
        # still honour a leading --home before the subcommand
        home = None
        if argv[0] == "run":
            ctx = Ctx(argparse.Namespace(home=home))
            try:
                return cmd_run(ctx, argv[1:])
            finally:
                ctx.close()
        else:
            ctx = Ctx(argparse.Namespace(home=home))
            try:
                return cmd_queue(ctx, argv[1:])
            finally:
                ctx.close()

    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 0

    ctx = Ctx(args)
    try:
        dispatch = {
            "jobs": lambda: cmd_jobs(ctx, args),
            "show": lambda: cmd_show(ctx, args),
            "resume": lambda: cmd_resume(ctx, args),
            "rm": lambda: cmd_rm(ctx, args),
            "report": lambda: cmd_report(ctx, args),
            "plan": lambda: cmd_plan(ctx, args),
            "mask": lambda: cmd_mask(ctx, args),
            "identify": lambda: cmd_identify(ctx, args),
            "benchmark": lambda: cmd_benchmark(ctx, args),
            "devices": lambda: cmd_devices(ctx, args),
            "eta": lambda: cmd_eta(ctx, args),
            "config": lambda: cmd_config(ctx, args),
        }
        handler = dispatch.get(args.cmd)
        if not handler:
            parser.print_help()
            return 2
        return handler()
    finally:
        ctx.close()
