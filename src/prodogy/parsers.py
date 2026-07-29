"""Parsers that turn raw files into :class:`ParsedArtifact` objects.

The YAML parser uses ruamel.yaml in round-trip mode so that every node carries
its source line number. This is what lets findings point at the exact line in a
PR comment. The Dockerfile parser is a small hand-rolled tokenizer that handles
line continuations and records the line where each instruction begins.

Both parsers are defensive: a malformed file yields a ParsedArtifact with
``data=None`` rather than raising, so one bad file never aborts a whole scan.
"""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from prodogy.engine import ParsedArtifact
from prodogy.models import FileKind

_yaml = YAML(typ="rt")
_yaml.preserve_quotes = True


class DockerInstruction:
    """A single Dockerfile instruction with its source line (1-based)."""

    __slots__ = ("cmd", "value", "line")

    def __init__(self, cmd: str, value: str, line: int) -> None:
        self.cmd = cmd.upper()
        self.value = value
        self.line = line

    def __repr__(self) -> str:  # pragma: no cover
        return f"DockerInstruction({self.cmd!r}, {self.value!r}, line={self.line})"


def parse_dockerfile(text: str) -> list[DockerInstruction]:
    """Parse Dockerfile text into instructions, handling `\\` continuations."""
    instructions: list[DockerInstruction] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        start_line = i + 1
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        # Accumulate continued lines.
        buffer = raw
        while buffer.rstrip().endswith("\\") and i < n:
            buffer = buffer.rstrip()[:-1] + " " + lines[i]
            i += 1
        buffer = buffer.strip()
        parts = buffer.split(None, 1)
        if not parts:
            continue
        cmd = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""
        instructions.append(DockerInstruction(cmd, value, start_line))
    return instructions


def parse_yaml_documents(text: str) -> tuple[list[object], str]:
    """Parse a possibly multi-document YAML file.

    Returns ``(documents, error)``. On success ``error`` is empty. On failure
    ``documents`` is empty and ``error`` holds a short description so callers
    can surface an "unparseable file" finding instead of silently passing.
    """
    docs: list[object] = []
    try:
        for doc in _yaml.load_all(text):
            if doc is not None:
                docs.append(doc)
    except YAMLError as exc:
        return [], _short_error(str(exc))
    return docs, ""


def _short_error(msg: str) -> str:
    # ruamel errors are multi-line and verbose; keep the first meaningful line.
    for line in msg.splitlines():
        line = line.strip()
        if line and not line.startswith("in \"<"):
            return line
    return msg.strip().splitlines()[0] if msg.strip() else "YAML parse error"


def load_artifact(path: Path, kind: FileKind) -> ParsedArtifact:
    """Read and parse a file into a :class:`ParsedArtifact`."""
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ParsedArtifact(path=str(path), kind=kind, data=None, lines=[], raw="")

    lines = raw.splitlines()
    parse_error = ""

    if kind is FileKind.DOCKERFILE:
        data: object = parse_dockerfile(raw)
    elif kind in {
        FileKind.K8S_DEPLOYMENT,
        FileKind.K8S_STATEFULSET,
        FileKind.K8S_MANIFEST,
        FileKind.HELM_VALUES,
        FileKind.GITHUB_ACTIONS,
        FileKind.GITLAB_CI,
        FileKind.DOCKER_COMPOSE,
        FileKind.GRAFANA,
        FileKind.PROMETHEUS,
        FileKind.ANSIBLE,
    }:
        data, parse_error = parse_yaml_documents(raw)
    else:
        # ENV files and unknowns are handled at the text level by their rules.
        data = None

    return ParsedArtifact(
        path=str(path), kind=kind, data=data, lines=lines, raw=raw, parse_error=parse_error
    )
