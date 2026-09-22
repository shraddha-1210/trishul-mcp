"""Trishul Milestone 1 — Step 3: preprocessing + taxonomy map + split.

Order (per locked-in owner decisions):
  a. Load 6 raw sources (MCP-SafetyBench dropped -> data/reserved/; OWASP reference-only).
  b. Apply taxonomy mapping to the 18-class Trishul taxonomy (+ benign).
  c. Emit normalized records (schema below).
  d. Apply Layer 1.5 canonicalization (training/canonicalize.py, == impl §3.2).
  e. Deduplicate by BLAKE3 of canonical text.
  f. Stratified 80/10/10 split by trishul_class, seed=42 (real data only).
  g. Write data/processed/{train_real,val,test}.jsonl.
  h. Print the Step 3 report; update DATA_CARD.md is done separately.

Fail-loud rules enforced here:
  - MCPSecBench category not in the confirmed map -> HELD (not dropped, not bucketed),
    listed for owner ruling; the script still writes the mapped data.
  - Dedup > 30% for any source -> printed as a STOP flag.
  - Any emitted trishul_class outside the 18-class taxonomy -> hard error.

Record schema:
  { id, text, trishul_class, source, impact_category?, attack_template?, raw_label }
"""
from __future__ import annotations

import csv
import glob
import json
import os
import random
from collections import Counter, defaultdict
from pathlib import Path

import blake3
from datasets import load_dataset

from canonicalize import canonicalize

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"
SEED = 42

TRISHUL_CLASSES = {
    "tool_description_poisoning", "rugpull_redefinition", "indirect_prompt_injection",
    "data_exfiltration", "unicode_tag_smuggling", "zero_width_obfuscation",
    "homoglyph_substitution", "cross_call_split_payload", "secret_credential_leak",
    "phishing_url_injection", "ocr_image_injection", "audio_injection", "jailbreak_payload",
    "schema_drift", "confused_deputy_exfil", "denial_of_wallet", "command_code_injection",
    "pii_harvesting", "benign",
}

# Confirmed MCPSecBench attack -> Trishul class (from owner-reviewed mapping).
# Any attack value NOT present here and not in MCPSECBENCH_DROP is HELD for an
# owner ruling (never bucketed).
MCPSECBENCH_MAP = {
    "Tool Poisoning Attack": "tool_description_poisoning",
    "Data Exfiltration": "data_exfiltration",
    "Rug Pull": "rugpull_redefinition",
    "Indirect Prompt Injection": "indirect_prompt_injection",
    # STOP 3 ruling (owner, Step 4): 3 of the 7 held categories mapped.
    "Tool Shadowing Attack": "tool_description_poisoning",
    "Prompt Injection": "indirect_prompt_injection",          # direct-injection row
    "Tool Misuse via Confused AI": "indirect_prompt_injection",
}

# STOP 3 ruling (owner, Step 4): the remaining 4 held categories are DROPPED —
# they are infrastructure/supply-chain attacks with no tool-response text signal,
# so they cannot train a Layer 4 text classifier. Kept out of the corpus, not
# silently bucketed.
MCPSECBENCH_DROP = {
    "Package Name Squatting(Server Name)",
    "Package Name Squatting(Tool Name)",
    "Sandbox Escape",
    "Vulnerable Server",
}


def _hash(text: str) -> str:
    return blake3.blake3(text.encode("utf-8")).hexdigest()[:16]


def _rec(text: str, cls: str, source: str, raw_label: str,
         impact_category=None, attack_template=None) -> dict:
    c = canonicalize(text)
    return {
        "id": f"{source}_{_hash(c.text)}",
        "text": c.text,
        "trishul_class": cls,
        "source": source,
        "impact_category": impact_category,
        "attack_template": attack_template,
        "raw_label": raw_label,
    }


# ---- per-source loaders -------------------------------------------------------

def load_mcptox() -> list[dict]:
    d = json.load(open(RAW / "mcptox" / "response_all.json", encoding="utf-8"))
    recs = []
    for sv in d["servers"].values():
        for m in sv.get("malicious_instance", []):
            md = m.get("metadata", {}) or {}
            text = m.get("poisoned_tool") or ""
            if not text.strip():
                continue
            recs.append(_rec(
                text=text,
                cls="tool_description_poisoning",  # Option A: all MCPTox rows
                source="mcptox",
                raw_label=md.get("security risk", "<none>"),
                impact_category=md.get("security risk"),
                attack_template=md.get("paradigm"),
            ))
    return recs


def load_mcpsecbench() -> tuple[list[dict], list[str]]:
    d = json.load(open(RAW / "mcpsecbench" / "data" / "data.json", encoding="utf-8"))
    recs, held = [], []
    for r in d:
        attack = r.get("attack", "<none>")
        cls = MCPSECBENCH_MAP.get(attack)
        text = (r.get("prompt") or "").strip()
        if attack in MCPSECBENCH_DROP:
            continue  # STOP 3: dropped by owner ruling
        if cls is None:
            held.append(attack)  # HELD for owner ruling
            continue
        if not text:
            continue
        recs.append(_rec(text=text, cls=cls, source="mcpsecbench", raw_label=attack))
    return recs, held


def load_deepset() -> list[dict]:
    ds = load_dataset("deepset/prompt-injections")
    recs = []
    for split in ds:
        for row in ds[split]:
            lbl = int(row["label"])
            cls = "indirect_prompt_injection" if lbl == 1 else "benign"
            text = (row.get("text") or "").strip()
            if not text:
                continue
            recs.append(_rec(text=text, cls=cls, source="deepset", raw_label=str(lbl)))
    return recs


def load_jackhhao() -> list[dict]:
    ds = load_dataset("jackhhao/jailbreak-classification")
    recs = []
    for split in ds:
        for row in ds[split]:
            t = row.get("type", "")
            cls = "jailbreak_payload" if t == "jailbreak" else "benign"
            text = (row.get("prompt") or "").strip()
            if not text:
                continue
            recs.append(_rec(text=text, cls=cls, source="jackhhao", raw_label=t))
    return recs


# ---- dedup + split ------------------------------------------------------------

def dedup(recs: list[dict]) -> tuple[list[dict], Counter, Counter]:
    seen: set[str] = set()
    kept, per_src_total, per_src_dup = [], Counter(), Counter()
    for r in recs:
        per_src_total[r["source"]] += 1
        h = _hash(r["text"])
        if h in seen:
            per_src_dup[r["source"]] += 1
            continue
        seen.add(h)
        kept.append(r)
    return kept, per_src_total, per_src_dup


def stratified_split(recs: list[dict], seed: int = SEED):
    by_cls = defaultdict(list)
    for r in recs:
        by_cls[r["trishul_class"]].append(r)
    rng = random.Random(seed)
    train, val, test = [], [], []
    for cls, items in by_cls.items():
        rng.shuffle(items)
        n = len(items)
        n_test = int(n * 0.10)
        n_val = int(n * 0.10)
        test += items[:n_test]
        val += items[n_test:n_test + n_val]
        train += items[n_test + n_val:]
    return train, val, test


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---- main ---------------------------------------------------------------------

def main() -> int:
    print(f"[seed] {SEED}")
    all_recs: list[dict] = []
    pre_counts = Counter()

    mcptox = load_mcptox(); all_recs += mcptox; pre_counts["mcptox"] = len(mcptox)
    secb, held = load_mcpsecbench(); all_recs += secb; pre_counts["mcpsecbench"] = len(secb)
    dp = load_deepset(); all_recs += dp; pre_counts["deepset"] = len(dp)
    jh = load_jackhhao(); all_recs += jh; pre_counts["jackhhao"] = len(jh)

    # sanity: every emitted class in taxonomy
    bad = {r["trishul_class"] for r in all_recs} - TRISHUL_CLASSES
    if bad:
        raise SystemExit(f"FATAL: emitted classes outside taxonomy: {bad}")

    kept, per_src_total, per_src_dup = dedup(all_recs)

    # dedup-rate flags
    dedup_flags = []
    for src, tot in per_src_total.items():
        rate = per_src_dup[src] / tot if tot else 0.0
        if rate > 0.30:
            dedup_flags.append((src, rate))

    train, val, test = stratified_split(kept)
    write_jsonl(OUT / "train_real.jsonl", train)
    write_jsonl(OUT / "val.jsonl", val)
    write_jsonl(OUT / "test.jsonl", test)

    # ---- report ----
    print("\n=== per-source pre-dedup / post-dedup ===")
    for src in ["mcptox", "mcpsecbench", "deepset", "jackhhao"]:
        tot = per_src_total[src]; dup = per_src_dup[src]
        rate = (dup / tot * 100) if tot else 0.0
        print(f"  {src:12s} pre={tot:5d}  dup={dup:5d}  post={tot-dup:5d}  dedup={rate:5.1f}%")

    print("\n=== per Trishul-class real-data totals (post-dedup) ===")
    cls_counts = Counter(r["trishul_class"] for r in kept)
    for cls in sorted(TRISHUL_CLASSES):
        n = cls_counts.get(cls, 0)
        flag = "  <-- BELOW 500 (synthetic needed)" if 0 < n < 500 else (
            "  <-- ZERO (synthetic only)" if n == 0 else "")
        print(f"  {cls:28s} {n:5d}{flag}")

    print("\n=== split verification (per-class train/val/test) ===")
    tr = Counter(r["trishul_class"] for r in train)
    va = Counter(r["trishul_class"] for r in val)
    te = Counter(r["trishul_class"] for r in test)
    for cls in sorted(c for c in cls_counts if cls_counts[c] > 0):
        print(f"  {cls:28s} train={tr.get(cls,0):5d} val={va.get(cls,0):4d} test={te.get(cls,0):4d}")
    print(f"  TOTAL train_real={len(train)} val={len(val)} test={len(test)}")

    if held:
        print("\n=== STOP-AND-ASK: HELD MCPSecBench categories (not dropped, not bucketed) ===")
        for lbl, c in Counter(held).most_common():
            print(f"  HELD  {c:3d}  {lbl}")

    if dedup_flags:
        print("\n=== STOP FLAG: dedup > 30% ===")
        for src, rate in dedup_flags:
            print(f"  {src}: {rate*100:.1f}%")

    print("\n[done] wrote train_real.jsonl / val.jsonl / test.jsonl to data/processed/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
