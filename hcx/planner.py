"""Attack planning: turn a target + resources into an ordered list of
hashcat invocations, and generate mask series. A plan is just data; the
job manager is what actually runs or queues each step, so every step is a
plain, inspectable hashcat command you could also run by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import tuning


@dataclass
class Step:
    name: str
    args: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "args": self.args}


def _base(mode: int, attack: int, hashfile: str) -> List[str]:
    return ["-m", str(mode), "-a", str(attack), hashfile]


def mask_series(
    charset: str = "?a",
    min_len: int = 1,
    max_len: int = 8,
) -> List[str]:
    """Produce explicit masks of increasing length, e.g. ?a, ?a?a, ..."""
    return [charset * n for n in range(min_len, max_len + 1)]


def build_plan(
    hashfile: str,
    mode: int,
    wordlists: Optional[List[str]] = None,
    rules: Optional[List[str]] = None,
    masks: Optional[List[str]] = None,
    profile: str = "standard",
    max_mask_len: int = 8,
) -> List[Step]:
    """Compose an ordered attack plan.

    profile:
      quick     - wordlists raw, then wordlists + rules
      standard  - quick, then an incremental brute up to max_mask_len
      thorough  - standard, plus combinator (needs 2 wordlists) and custom masks
    """
    wordlists = wordlists or []
    rules = rules or []
    masks = masks or []
    slow = tuning.is_slow_mode(mode)
    steps: List[Step] = []

    # 1) Straight dictionary pass (cheapest, highest value first).
    for wl in wordlists:
        steps.append(Step(f"dict:{_short(wl)}", _base(mode, 0, hashfile) + [wl]))

    # 2) Dictionary + rules (the workhorse for slow hashes especially).
    for wl in wordlists:
        for rule in rules:
            steps.append(
                Step(
                    f"dict+rules:{_short(wl)}+{_short(rule)}",
                    _base(mode, 0, hashfile) + [wl, "-r", rule],
                )
            )

    if profile in ("standard", "thorough") and not slow:
        # 3) Incremental brute force. Slow hashes skip this on purpose:
        #    brute force is rarely worthwhile against KDFs.
        for m in mask_series("?a", 1, max_mask_len):
            steps.append(Step(f"brute:{m}", _base(mode, 3, hashfile) + [m]))

    if profile == "thorough":
        # 4) Combinator across the first two wordlists.
        if len(wordlists) >= 2:
            steps.append(
                Step(
                    f"combine:{_short(wordlists[0])}+{_short(wordlists[1])}",
                    _base(mode, 1, hashfile) + [wordlists[0], wordlists[1]],
                )
            )
        # 5) Any explicit custom masks the caller supplied.
        for m in masks:
            steps.append(Step(f"mask:{m}", _base(mode, 3, hashfile) + [m]))

    if not steps:
        raise SystemExit(
            "empty plan: provide at least one --wordlist, or use a mask profile"
        )
    return steps


def describe(steps: List[Step]) -> str:
    lines = []
    for i, s in enumerate(steps, 1):
        lines.append(f"  {i:>2}. {s.name}")
        lines.append(f"      hashcat {' '.join(s.args)}")
    return "\n".join(lines)


def _short(path: str) -> str:
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return base
