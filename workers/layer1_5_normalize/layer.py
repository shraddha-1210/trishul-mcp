"""Layer 1.5 — normalization and de-obfuscation (implementation.md §3.2).

Wraps training/canonicalize.py, which stays the byte-for-byte source of truth for
NFKC + invisible-char stripping + base64 recursion. Two steps are added on top,
because canonicalize alone cannot satisfy the demo attacks:

  * Tag-block reveal. canonicalize *deletes* U+E0000..U+E007F, which hides a
    smuggled instruction from every later layer. Before that happens we decode
    U+E0020..U+E007E back to ASCII and append it to the canonical text (the same
    way canonicalize appends decoded base64), so Layer 2a / Layer 4 see it.
  * Homoglyph fold. NFKC does not map Cyrillic/Greek look-alikes to Latin
    (U+0406 stays U+0406). Inside any word that mixes Latin letters with
    confusables, the confusables are folded to Latin. Words with no Latin letters
    (real Russian, Greek, ...) are left alone.

NOTE: these two steps are not in training/canonicalize.py, so training text for
tag-block / homoglyph samples differs from inference text. See the Step 1 report.

Fails closed: undecodable input raises NormalizationError (reason
"encoding_error"); the caller turns that into BLOCK.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

_CANON_PATH = Path(__file__).resolve().parents[2] / "training" / "canonicalize.py"
_spec = importlib.util.spec_from_file_location("trishul_canonicalize", _CANON_PATH)
_canon = sys.modules.setdefault(_spec.name, importlib.util.module_from_spec(_spec))
_spec.loader.exec_module(_canon)
canonicalize = _canon.canonicalize

TAG_BASE = 0xE0000

# Classification of canonicalize.STRIP_RANGES for reporting.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0xFEFF}
_BIDI = {0x200E, 0x200F} | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))

# High-confidence confusables -> Latin (subset of Unicode confusables.txt).
HOMOGLYPHS = {
    # Cyrillic uppercase
    "Ѕ": "S", "І": "I", "Ј": "J", "А": "A", "В": "B",
    "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ү": "Y",
    "ԁ": "d",
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i",
    "ј": "j", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    # Greek
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o",
}
_WORD = re.compile(r"[^\W\d_]+")


class NormalizationError(ValueError):
    """Input could not be normalized. Callers must treat this as BLOCK."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


@dataclass
class NormalizationResult:
    canonical_text: str
    was_obfuscated: bool
    stripped_chars_count: int
    stripped_types: list[str]  # subset of zero_width, tag_block, homoglyph, bidi
    original_len: int = 0
    hidden_text: str = ""  # instruction recovered from a tag block, if any
    homoglyph_count: int = 0
    transformations: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


def _is_latin_letter(ch: str) -> bool:
    if ch.isascii():
        return ch.isalpha()
    return unicodedata.name(ch, "").startswith("LATIN")


def fold_homoglyphs(text: str) -> tuple[str, int]:
    """Fold confusables to Latin inside mixed-script words. Returns (text, count)."""
    if text.isascii():
        return text, 0
    count = 0

    def fix(m: re.Match) -> str:
        nonlocal count
        word = m.group(0)
        if word.isascii() or not any(c in HOMOGLYPHS for c in word):
            return word
        if not any(_is_latin_letter(c) for c in word if c not in HOMOGLYPHS):
            return word  # no genuine Latin letters: real non-Latin text
        out = []
        for c in word:
            if c in HOMOGLYPHS:
                count += 1
                out.append(HOMOGLYPHS[c])
            else:
                out.append(c)
        return "".join(out)

    return _WORD.sub(fix, text), count


def reveal_tag_block(text: str) -> str:
    """Decode tag characters back to ASCII. Separate tag runs are space-joined."""
    runs: list[str] = []
    cur: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            cur.append(chr(cp - TAG_BASE))
        elif cur:
            runs.append("".join(cur))
            cur = []
    if cur:
        runs.append("".join(cur))
    return " ".join(r for r in runs if r.strip())


def _classify_stripped(nfkc_text: str) -> dict[str, int]:
    counts = {"zero_width": 0, "tag_block": 0, "bidi": 0}
    for ch in nfkc_text:
        cp = ord(ch)
        if cp in _ZERO_WIDTH:
            counts["zero_width"] += 1
        elif cp in _BIDI:
            counts["bidi"] += 1
        elif 0xE0000 <= cp <= 0xE007F:
            counts["tag_block"] += 1
    return counts


# TODO: optimize for larger inputs post-demo. Measured P95: 1 KB 1.2 ms, 10 KB 12 ms,
# 100 KB 109 ms (budget 3 ms). Cost is canonicalize's per-char range scan.
def normalize(text: str | bytes) -> NormalizationResult:
    t0 = time.perf_counter()
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as e:
            raise NormalizationError("encoding_error", str(e)) from e
    if not isinstance(text, str):
        raise NormalizationError("encoding_error", f"expected str or bytes, got {type(text).__name__}")
    try:
        text.encode("utf-8")  # rejects lone surrogates (e.g. surrogateescape'd bad bytes)
    except UnicodeEncodeError as e:
        raise NormalizationError("encoding_error", str(e)) from e

    hidden = reveal_tag_block(text)
    by_type = _classify_stripped(unicodedata.normalize("NFKC", text))

    cr = canonicalize(text)
    folded, n_homo = fold_homoglyphs(cr.text)
    transformations = list(cr.transformations)
    if n_homo:
        transformations.append("homoglyph_fold")
    if hidden:
        transformations.append("tag_block_reveal")
        sep = "" if not folded or folded[-1].isspace() else " "
        folded = f"{folded}{sep}{hidden}"

    stripped_types = [k for k in ("zero_width", "tag_block", "homoglyph", "bidi")
                      if (n_homo if k == "homoglyph" else by_type[k])]

    return NormalizationResult(
        canonical_text=folded,
        was_obfuscated=cr.was_obfuscated or n_homo > 0,
        stripped_chars_count=cr.stripped_len,
        stripped_types=stripped_types,
        original_len=cr.original_len,
        hidden_text=hidden,
        homoglyph_count=n_homo,
        transformations=transformations,
        latency_ms=(time.perf_counter() - t0) * 1000,
    )
