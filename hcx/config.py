"""Configuration and path discovery for hcx.

Resolves where the hashcat binary lives and where hcx keeps its own
state (database, sessions, potfile, logs). Nothing here is required to
be set manually: sane defaults are derived from the environment and the
host, and anything can be overridden through the config file or env.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional

APP_NAME = "hcx"

# Environment overrides (highest priority after explicit CLI flags).
ENV_HASHCAT = "HCX_HASHCAT"       # path to the hashcat binary
ENV_HOME = "HCX_HOME"             # hcx working/state directory


def _default_home() -> Path:
    """Pick a per-user state directory following platform conventions."""
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


def _candidate_binaries() -> list:
    names = ["hashcat.exe", "hashcat.bin", "hashcat"]
    found = []
    for name in names:
        p = shutil.which(name)
        if p:
            found.append(Path(p))
    # Common sibling layout: hashcat distribution unpacked next to hcx.
    here = Path(__file__).resolve()
    for up in (here.parent, *here.parents[:4]):
        for name in names:
            cand = up / name
            if cand.is_file():
                found.append(cand)
    return found


class Config:
    def __init__(self, home: Optional[Path] = None):
        self.home = Path(home) if home else _default_home()
        self.config_path = self.home / "config.json"
        self._data: Dict[str, Any] = {}
        self._load()

    # --- persistence -----------------------------------------------------
    def _load(self) -> None:
        if self.config_path.is_file():
            try:
                self._data = json.loads(self.config_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                self._data = {}

    def save(self) -> None:
        self.ensure_dirs()
        self.config_path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    # --- derived paths ---------------------------------------------------
    def ensure_dirs(self) -> None:
        for d in (self.home, self.sessions_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)

    @property
    def db_path(self) -> Path:
        return self.home / "hcx.db"

    @property
    def sessions_dir(self) -> Path:
        return self.home / "sessions"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def potfile_path(self) -> Path:
        configured = self._data.get("potfile")
        if configured:
            return Path(configured).expanduser()
        return self.home / "hcx.potfile"

    # --- hashcat binary --------------------------------------------------
    def hashcat_binary(self) -> Optional[Path]:
        """Resolve the hashcat binary. Order: env, config, PATH, siblings."""
        env = os.environ.get(ENV_HASHCAT)
        if env and Path(env).is_file():
            return Path(env)
        configured = self._data.get("hashcat")
        if configured and Path(configured).is_file():
            return Path(configured)
        cands = _candidate_binaries()
        return cands[0] if cands else None

    def require_hashcat(self) -> Path:
        b = self.hashcat_binary()
        if not b:
            raise SystemExit(
                "hashcat binary not found. Set it with:\n"
                "  hcx config set-hashcat <path-to-hashcat.exe>\n"
                f"or export {ENV_HASHCAT}=<path>, or put hashcat on your PATH."
            )
        return b

    def as_dict(self) -> Dict[str, Any]:
        return {
            "home": str(self.home),
            "db": str(self.db_path),
            "potfile": str(self.potfile_path),
            "hashcat": str(self.hashcat_binary() or ""),
            **self._data,
        }
