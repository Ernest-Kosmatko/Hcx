# ⬡ Hcx

> **Orchestration Layer for Hashcat**
> Job management, reporting, attack planning, hash identification and tuning — bolted onto the stock `hashcat` binary without changing a thing it does.

[![CI](https://github.com/Ernest-Kosmatko/Hcx/actions/workflows/ci.yml/badge.svg)](https://github.com/Ernest-Kosmatko/Hcx/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Dependencies: none](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)](pyproject.toml)

---

## 🔍 What is Hcx?

Hcx wraps [hashcat](https://hashcat.net/hashcat/) and adds the glue every engagement ends up needing by hand:

- **Jobs** — every run recorded (command, session, progress, outcome, log); resume or queue them
- **Reports** — parse the potfile / outfile, see crack rate and password insights, export CSV / JSON / HTML
- **Planner** — turn a target + wordlists + rules into an ordered attack plan (dictionary → rules → brute/combinator)
- **Identify** — delegates to hashcat's own `--identify`, with an instant offline heuristic fallback
- **Tuning** — benchmark and store device speeds, estimate keyspace/ETA for any mask, list backend devices

Every original hashcat flag is passed straight through. `hcx run -- <anything>` is hashcat, with a managed session, a captured log, a shared potfile and a live dashboard on top — nothing hidden, nothing overridden.

Pure Python standard library. No external runtime dependencies. Python 3.8+.

---

## 📸 Sample Session

```
$ hcx identify 8743b52063cd84097a65d1633f5c74f5
[*] Identifying hash via hashcat --identify...
  [+] Mode 0   MD5
  [+] Mode 900 MD4

$ hcx run --name demo -- -m 0 -a 0 hashes.txt rockyou.txt -r rules/best64.rule
[*] Session: demo  |  Job: job_0007
[*] Launching hashcat (managed session, live dashboard)...
  Progress ......: 41.2% (12,450,112 / 30,208,640)
  Speed .........: 1,842.3 MH/s
  Recovered .....: 3/5 hashes

$ hcx jobs
  ID       NAME   STATUS     RECOVERED   STARTED
  job_0007 demo   finished   5/5         2026-10-19 14:02

$ hcx report summary
  Hashes cracked ..: 5
  Crack rate ......: 100%
  Top pattern .....: 8 chars, lowercase+digit

$ hcx report export --source potfile --format html --out loot.html
[+] Report written: loot.html
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- A local `hashcat` build
- Hashes you are **authorized** to attempt to recover

### Installation

```bash
git clone https://github.com/Ernest-Kosmatko/Hcx.git
cd Hcx
pip install -e .
# or run in place without installing:
python -m hcx --help
```

### Point it at hashcat

Hcx auto-detects `hashcat` on `PATH`, next to itself, or via `$HCX_HASHCAT`.

```bash
hcx config set-hashcat /path/to/hashcat.exe
hcx config show
```

### Usage

```bash
# Identify a hash
hcx identify 8743b52063cd84097a65d1633f5c74f5

# Run an attack — everything after -- is raw hashcat, untouched
hcx run --name demo -- -m 0 -a 0 hashes.txt rockyou.txt -r rules/best64.rule

# History and results
hcx jobs
hcx report summary
hcx report export --source potfile --format html --out loot.html

# Build and run a multi-step attack plan
hcx plan --hashfile hashes.txt --mode 0 \
    --wordlist rockyou.txt --rule rules/best64.rule --profile thorough --run

# Hardware + timing
hcx benchmark -m 0
hcx devices
hcx eta --mask ?a?a?a?a?a?a?a?a --mode 0
```

---

## 🧭 Commands

| Command | Purpose |
|---|---|
| `run` | Run one attack (args after `--` go verbatim to hashcat) |
| `queue add / list / run / clear` | Build and execute a sequential attack queue |
| `jobs` / `show` / `resume` / `rm` | Job history and session control |
| `report summary / potfile / job / export` | Results, stats and exports |
| `plan` | Compose, queue or run a multi-step attack plan |
| `mask` | Generate a mask series with keyspace sizes |
| `identify` | Identify a hash mode |
| `benchmark` / `devices` / `eta` | Speed, hardware and time estimates |
| `config` | Show or change configuration |

---

## 🏗️ Project Structure

```
Hcx/
├── hcx/
│   ├── __main__.py     # `python -m hcx` entry point
│   ├── cli.py           # argparse + command dispatch
│   ├── jobs.py           # managed command construction, run/queue/resume
│   ├── runner.py         # subprocess handling, live --status-json dashboard, logging
│   ├── store.py           # SQLite persistence (jobs, benchmarks)
│   ├── report.py           # potfile/outfile parsing, stats, CSV/JSON/HTML export
│   ├── planner.py           # attack plans + mask series
│   ├── identify.py           # hashcat --identify + offline heuristic
│   ├── tuning.py               # benchmark, devices, keyspace/ETA, advice
│   ├── config.py                 # paths + hashcat discovery
│   └── util.py
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## 💾 State

Hcx keeps its state under a per-user directory — `%APPDATA%\hcx` on Windows, `~/.local/share/hcx` on Linux, `~/Library/Application Support/hcx` on macOS: a SQLite job database, per-job logs, restore files and outfiles, and a shared potfile. Override with `$HCX_HOME` or `--home`. None of this is written into the repository.

---

## ⚠️ Legal Disclaimer

**This tool is for authorized use only.**
Hcx orchestrates hashcat; it does not change what you are permitted to do with it. Attempting to recover credentials you do not own or do not have explicit, written authorization to test is illegal in most jurisdictions.

The author assumes no liability for misuse of this software.
**Always get written authorization before attacking any hash set.**

---

## 📄 License

[MIT](LICENSE) © Ernest Kosmatko. hashcat itself is a separate project under its own license.

---

## 👤 Author

**Ernest Kosmatko**
GitHub: [@Ernest-Kosmatko](https://github.com/Ernest-Kosmatko)
