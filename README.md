# Hcx

An orchestration layer for [hashcat](https://hashcat.net/hashcat/). It wraps the
stock hashcat binary and adds the glue you end up writing by hand on every
engagement — job management, reporting, attack planning, hash identification and
tuning — without changing, hiding or removing any of hashcat's own behaviour.

Every original hashcat flag is passed straight through. `hcx run -- <anything>`
is just hashcat with a managed session, a captured log, a shared potfile and a
tidy live dashboard bolted on.

## Why

Running hashcat seriously means juggling sessions, restore files, outfiles,
potfiles and a pile of shell history. hcx keeps all of that in one place:

- **Jobs** — every run is recorded (command, session, progress, outcome, log).
  Resume any job with `hcx resume <id>`; queue many and run them back to back.
- **Reports** — parse the potfile / per-job outfile, see crack rate and password
  insights, export to CSV / JSON / a standalone HTML report.
- **Planner** — turn a target + wordlists + rules into an ordered attack plan
  (dictionary → rules → brute/combinator), inspect it, then queue or run it.
- **Identify** — delegate to hashcat's own `--identify`, with an instant offline
  heuristic fallback.
- **Tuning** — benchmark and store device speeds, estimate keyspace/ETA for any
  mask, list backend devices, get workload advice.

No external dependencies. Pure Python standard library, 3.8+.

## Install

```bash
pip install -e .
# or just run it in place:
python -m hcx --help
```

## Point it at hashcat

hcx auto-detects hashcat on your `PATH`, next to itself, or via `$HCX_HASHCAT`.
To set it explicitly:

```bash
hcx config set-hashcat /path/to/hashcat.exe
hcx config show
```

## Quick start

```bash
# identify a hash
hcx identify 8743b52063cd84097a65d1633f5c74f5

# run an attack (everything after -- is raw hashcat)
hcx run --name demo -- -m 0 -a 0 hashes.txt rockyou.txt -r rules/best64.rule

# see history, then a report
hcx jobs
hcx report summary
hcx report export --source potfile --format html --out loot.html

# build and run a plan
hcx plan --hashfile hashes.txt --mode 0 \
    --wordlist rockyou.txt --rule rules/best64.rule --profile thorough --run

# benchmark + ETA
hcx benchmark -m 0
hcx eta --mask ?a?a?a?a?a?a?a?a --mode 0
```

## Commands

| command | purpose |
|---|---|
| `run` | run one attack (args after `--` go verbatim to hashcat) |
| `queue add/list/run/clear` | build and execute a sequential attack queue |
| `jobs` / `show` / `resume` / `rm` | job history and session control |
| `report summary/potfile/job/export` | results, stats and exports |
| `plan` | compose, queue or run a multi-step attack plan |
| `mask` | generate a mask series with keyspace sizes |
| `identify` | identify a hash mode |
| `benchmark` / `devices` / `eta` | speed, hardware and time estimates |
| `config` | show / set configuration |

## State

hcx keeps its state under a per-user directory (`%APPDATA%\hcx` on Windows,
`~/.local/share/hcx` on Linux, `~/Library/Application Support/hcx` on macOS):
a SQLite job database, per-job logs, restore files and outfiles, and a shared
potfile. Override with `$HCX_HOME` or `--home`.

## License

MIT. hashcat itself is a separate project under its own license.
