"""Layer 2a — known-attack pattern match (implementation.md §3.3).

Case-insensitive fixed-string matching with an Aho-Corasick automaton over the
Layer 1.5 canonical text, so cost is linear in input length regardless of how
many signatures are loaded.

The signature file is loaded and compiled at import time: if it is missing,
empty or malformed, import raises and the backend refuses to start.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import ahocorasick

DEFAULT_PATTERNS = Path(__file__).resolve().parent / "patterns" / "known_attacks.txt"


class PatternLoadError(RuntimeError):
    """Signature file unusable. The layer must not run without its signatures."""


class PatternScanError(ValueError):
    """Input could not be scanned. Callers must treat this as BLOCK."""


@dataclass
class ScanResult:
    matched: bool
    matched_spans: list[tuple[int, int]]  # [start, end) into the scanned text
    matched_patterns: list[str]  # unique, in order of first match
    latency_ms: float
    categories: list[str] = field(default_factory=list)


def load_patterns(path: Path = DEFAULT_PATTERNS) -> list[tuple[str, str]]:
    """Parse '<category> | <phrase>' lines. Returns [(category, lowercased phrase)]."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise PatternLoadError(f"cannot read signature file {path}: {e}") from e
    out: list[tuple[str, str]] = []
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        category, sep, phrase = line.partition(" | ")
        if not sep or not category.strip() or not phrase.strip():
            raise PatternLoadError(f"{path}:{n}: expected '<category> | <phrase>', got {raw!r}")
        out.append((category.strip(), phrase.strip().lower()))
    if not out:
        raise PatternLoadError(f"signature file {path} has no patterns")
    return out


def build_automaton(patterns: list[tuple[str, str]]) -> ahocorasick.Automaton:
    a = ahocorasick.Automaton()
    for category, phrase in patterns:
        a.add_word(phrase, (category, phrase))
    a.make_automaton()
    return a


_AUTOMATON = build_automaton(load_patterns())


def _lower_same_length(text: str) -> str:
    """Lowercase without changing length, so match offsets index the original text."""
    if text.isascii():
        return text.lower()
    return "".join(lc if len(lc := c.lower()) == 1 else c for c in text)


def scan(text: str, automaton: ahocorasick.Automaton | None = None) -> ScanResult:
    t0 = time.perf_counter()
    if not isinstance(text, str):
        raise PatternScanError(f"expected str, got {type(text).__name__}")
    auto = automaton or _AUTOMATON
    low = _lower_same_length(text)

    spans: list[tuple[int, int]] = []
    patterns: list[str] = []
    categories: list[str] = []
    for end, (category, phrase) in auto.iter(low):
        start = end - len(phrase) + 1
        if phrase[0].isalnum() and start > 0 and low[start - 1].isalnum():
            continue  # left word boundary
        spans.append((start, end + 1))
        if phrase not in patterns:
            patterns.append(phrase)
        if category not in categories:
            categories.append(category)
    spans.sort()
    return ScanResult(
        matched=bool(spans),
        matched_spans=spans,
        matched_patterns=patterns,
        latency_ms=(time.perf_counter() - t0) * 1000,
        categories=categories,
    )
