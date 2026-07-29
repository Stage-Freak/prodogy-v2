"""Maintainability signals — the 'exceptional nudge' heatmap layer.

Computed from git history + light heuristics, entirely locally. No ML. The
output is a per-file ``heat`` score (0..1) plus the raw signals that produced
it, so the web UI can render a heatmap and explain each cell.

Signals:
  * change_frequency  — how often a file changes (churn).
  * last_changed_days — staleness; old + TODO-heavy files are neglected debt.
  * coupled_with      — files that change together in the same commits
                        (tight coupling hotspots).
  * todo_count        — TODO/FIXME/HACK markers in the file.

If the directory is not a git repo, we degrade gracefully: git-derived signals
are zero and only static ones (TODOs) are populated.
"""

from __future__ import annotations

import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from prodogy.models import MaintainabilitySignal, ScannedFile


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def _is_git_repo(root: Path) -> bool:
    return _git(root, "rev-parse", "--is-inside-work-tree") is not None


def _commit_history(root: Path) -> tuple[list[list[str]], dict[str, int]]:
    """Parse git history once, returning both co-change groups and last-changed.

    Returns ``(groups, last_changed_ts)`` where ``groups`` is a list of
    per-commit changed-file lists and ``last_changed_ts`` maps each file to the
    unix timestamp of the most recent commit that touched it. Doing this in a
    single ``git log`` pass avoids an O(n) subprocess-per-file cost on large
    repos (a key scalability fix).
    """
    # Marker line carries the commit timestamp: \x01<unix_ts>\x01
    out = _git(root, "log", "--name-only", "--pretty=format:%x01%ct%x01", "-n", "1000")
    if not out:
        return [], {}
    groups: list[list[str]] = []
    last_changed: dict[str, int] = {}
    current: list[str] = []
    current_ts = 0
    for line in out.splitlines():
        if line.startswith("\x01"):
            if current:
                groups.append(current)
            current = []
            try:
                current_ts = int(line.strip("\x01").strip() or 0)
            except ValueError:
                current_ts = 0
        elif line.strip():
            path = line.strip()
            current.append(path)
            # First time we see a file (newest commit first) is its last change.
            if path not in last_changed:
                last_changed[path] = current_ts
    if current:
        groups.append(current)
    return groups, last_changed


def _days_since(ts: int | None) -> int | None:
    if not ts:
        return None
    delta = datetime.now(timezone.utc) - datetime.fromtimestamp(ts, tz=timezone.utc)
    return max(delta.days, 0)


def _count_todos(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    count = 0
    for marker in ("TODO", "FIXME", "HACK", "XXX"):
        count += text.count(marker)
    return count


def _normalize(value: float, cap: float) -> float:
    if cap <= 0:
        return 0.0
    return min(value / cap, 1.0)


def compute_signals(root: Path, files: list[ScannedFile]) -> list[MaintainabilitySignal]:
    root = Path(root)
    tracked = {f.path for f in files}
    is_repo = _is_git_repo(root)

    change_freq: Counter[str] = Counter()
    cochange: dict[str, Counter[str]] = defaultdict(Counter)
    last_changed_ts: dict[str, int] = {}

    if is_repo:
        groups, last_changed_ts = _commit_history(root)
        for group in groups:
            relevant = [f for f in group if f in tracked]
            for f in relevant:
                change_freq[f] += 1
            # Co-change pairs within the same commit.
            for a in relevant:
                for b in relevant:
                    if a != b:
                        cochange[a][b] += 1

    signals: list[MaintainabilitySignal] = []
    max_freq = max(change_freq.values(), default=0)

    for f in files:
        rel = f.path
        abspath = root / rel
        freq = change_freq.get(rel, 0)
        todos = _count_todos(abspath)
        last_days = _days_since(last_changed_ts.get(rel)) if is_repo else None
        coupled = [name for name, cnt in cochange.get(rel, Counter()).most_common(5) if cnt >= 2]

        # Heat = weighted blend of churn, coupling, and neglected debt.
        churn_h = _normalize(freq, max_freq)
        coupling_h = _normalize(len(coupled), 5)
        # Neglected: old file (>180d) that still carries TODOs.
        neglect_h = 0.0
        if last_days is not None and last_days > 180 and todos > 0:
            neglect_h = _normalize(todos, 10)
        heat = round(min(0.5 * churn_h + 0.3 * coupling_h + 0.2 * neglect_h, 1.0), 3)

        signals.append(
            MaintainabilitySignal(
                path=rel,
                change_frequency=freq,
                last_changed_days=last_days,
                coupled_with=coupled,
                todo_count=todos,
                complexity_score=0.0,
                heat=heat,
            )
        )

    signals.sort(key=lambda s: s.heat, reverse=True)
    return signals
