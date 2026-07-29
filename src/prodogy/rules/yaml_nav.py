"""Helpers for navigating ruamel.yaml round-trip nodes with line numbers.

ruamel's CommentedMap / CommentedSeq expose ``.lc`` (line/column) data. These
helpers make it easy for rules to fetch a nested value and the source line where
a given key lives, so findings can point at the exact spot.

All helpers are null-safe: missing keys return ``None`` (or the provided
default) rather than raising, keeping rule code compact and robust.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

_MISSING = object()


def get(node: Any, *keys: str, default: Any = None) -> Any:
    """Safely walk a chain of mapping keys: ``get(doc, "spec", "template")``."""
    cur = node
    for key in keys:
        if not hasattr(cur, "get"):
            return default
        cur = cur.get(key, _MISSING)
        if cur is _MISSING:
            return default
    return cur


def key_line(node: Any, key: str) -> int | None:
    """Return the 1-based source line of ``key`` within a mapping node."""
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    try:
        data = lc.data  # dict: key -> (key_line, key_col, val_line, val_col)
    except AttributeError:
        return None
    if data and key in data:
        return int(data[key][0]) + 1
    return None


def node_line(node: Any) -> int | None:
    """Return the 1-based line where a node begins, if known."""
    lc = getattr(node, "lc", None)
    if lc is None or lc.line is None:
        return None
    return int(lc.line) + 1


def iter_containers(pod_spec: Any) -> Iterator[tuple[Any, int | None]]:
    """Yield ``(container_node, line)`` for containers + initContainers."""
    if not hasattr(pod_spec, "get"):
        return
    for field in ("containers", "initContainers"):
        seq = pod_spec.get(field)
        if not seq:
            continue
        for idx, container in enumerate(seq):
            line = None
            lc = getattr(seq, "lc", None)
            if lc is not None:
                try:
                    line = int(lc.data[idx][0]) + 1
                except (AttributeError, KeyError, IndexError, TypeError):
                    line = node_line(container)
            yield container, line


def pod_spec_of(doc: Any) -> Any:
    """Return the pod spec for a workload doc (Deployment/StatefulSet/etc.)."""
    # Workload controllers nest the pod under spec.template.spec.
    templated = get(doc, "spec", "template", "spec")
    if templated is not None:
        return templated
    # A bare Pod puts containers directly under spec.
    return get(doc, "spec")


def doc_kind(doc: Any) -> str:
    return str(get(doc, "kind", default="") or "")
