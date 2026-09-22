"""Trishul Milestone 1 - Step 4b: mass synthetic generation across all classes.

This is a SCHEDULER around the approved Step 4 pipeline. It does not change how a
candidate is produced or judged: the prompt (`generate_synthetic.build_prompt`),
the Ollama call (`ollama_generate`) and the full rejection chain (`accept` ->
`class_validators.validate`) are imported and used unmodified. Only the loop that
decides *what to generate next* is new.

Why a scheduler exists at all
-----------------------------
`generate_synthetic.paraphrase_class` runs ONE class to its floor before
returning, holding every kept row in memory. On this box (CPU-only Ollama,
llama3.1:8b) the calibration probe kept 20 rows in 1063s == ~53s per kept row, so
a single class at the 1500 floor is ~22 hours and ten classes is ~9 days. An
overnight run must therefore:

  1. ROUND-ROBIN across classes, one batch each pass, so a run cut short at any
     moment yields even coverage instead of one finished class and nine empty.
  2. CHECKPOINT after every batch, so a crash, a reboot or a Ctrl-C keeps
     everything generated up to that point.
  3. Be WALL-CLOCK BOUNDED (--budget-hours), because the deadline is fixed and
     the 1500 floor is not reachable before it.
  4. SKIP a class that is failing rather than stop the run (owner ruling:
     ">90% rejection -> skip that class and continue").

Output is quarantined per class in data/synth/<class>/synthetic.jsonl. This
script deliberately does NOT touch data/processed/train.jsonl; merging synthetic
rows into the training corpus stays a separate, reviewed step.

Resumable: re-running picks up the rows already on disk, re-seeds the dedupe
state from them, and continues toward the target.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests

import generate_synthetic as gs
from class_validators import SEV_LABELS, severity_categories

ROOT = Path(__file__).resolve().parents[1]
SYNTH = ROOT / "data" / "synth"
STATUS = SYNTH / "run_status.json"
LOG = SYNTH / "mass_gen.log"


def ready_classes() -> tuple[list[str], dict[str, str]]:
    """Classes that can actually be generated right now.

    A class needs BOTH a CLASS_SPEC (or `build_prompt` raises KeyError) and
    hand-written seeds (without them the pipeline falls back to real corpus rows,
    which is the exact anchoring mistake STOP 1 was about). Anything missing one
    is reported as NOT_READY rather than silently skipped.
    """
    ready, blocked = [], {}
    for cls in sorted(gs.PARAPHRASE_CLASSES):
        has_spec = cls in gs.CLASS_SPECS
        has_seeds = bool(gs.load_seeds(cls))
        if has_spec and has_seeds:
            ready.append(cls)
        else:
            missing = []
            if not has_spec:
                missing.append("no CLASS_SPEC in generate_synthetic.py")
            if not has_seeds:
                missing.append("no seeds at data/seeds/%s.jsonl" % cls)
            blocked[cls] = "; ".join(missing)
    return ready, blocked


# A class is only judged on its rejection rate once it has produced enough
# candidates for the rate to mean anything. The calibration probe ran at 77%
# rejection while producing rows the owner approved, so the bar is the owner's 90%.
MIN_SEEN_BEFORE_SKIP = 48
SKIP_REJECTION_RATE = 0.90
MAX_CONSECUTIVE_ERRORS = 3

# Only these are retried and reported as OLLAMA_ERROR: the server being down,
# slow, or answering with something that is not JSON. Deliberately NARROW --
# a bare `except Exception` here would relabel a bug in this file (a TypeError,
# an AttributeError) as "Ollama is unhealthy" and quietly degrade the run for
# hours. Anything else propagates: the per-batch checkpoint means a crash loses
# nothing, and a traceback is worth more than a misleading status.
TRANSIENT_ERRORS = (requests.RequestException, ValueError, OSError)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = "[%s] %s" % (now(), msg)
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def atomic_write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


class ClassState:
    def __init__(self, cls: str, seen: set):
        self.cls = cls
        self.seeds = gs.load_seeds(cls)
        self.real = len(gs.load_real(cls))
        self.out_dir = SYNTH / cls
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.out_path = self.out_dir / "synthetic.jsonl"
        self.rng = random.Random(sum(ord(ch) for ch in cls))
        self.rejections: dict = {}
        self.batches = 0
        self.errors = 0
        self.consecutive_errors = 0
        self.elapsed = 0.0
        self.status = "ACTIVE"
        self.note = ""
        # Dedupe / near-dupe state. Seeds anchor the near-dupe pool so generated
        # rows cannot be light rewrites of the few-shot examples themselves.
        self.token_pool = [gs._tokens(s) for s in self.seeds]
        for s in self.seeds:
            seen.add(gs._hash(s))
        self.kept = 0
        self._resume(seen)

    def _resume(self, seen: set) -> None:
        """Re-seed dedupe state from rows already generated by an earlier run."""
        if not self.out_path.exists():
            return
        for line in self.out_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            text = json.loads(line)["text"]
            seen.add(gs._hash(text))
            self.token_pool.append(gs._tokens(text))
            self.kept += 1
        if self.kept:
            log("  resume %s: %d rows already on disk" % (self.cls, self.kept))

    @property
    def seen_total(self) -> int:
        return self.kept + sum(self.rejections.values())

    @property
    def rejection_rate(self) -> float:
        return (sum(self.rejections.values()) / self.seen_total) if self.seen_total else 0.0

    def append(self, texts: list) -> None:
        with open(self.out_path, "a", encoding="utf-8") as f:
            for t in texts:
                f.write(json.dumps(gs.make_record(t, self.cls), ensure_ascii=False) + "\n")

    def _display_path(self) -> str:
        """Repo-relative when possible; absolute when SYNTH is redirected (tests)."""
        try:
            return str(self.out_path.relative_to(ROOT))
        except ValueError:
            return str(self.out_path)

    def summary(self) -> dict:
        sev: dict = {}
        if self.out_path.exists():
            for line in self.out_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    for c in severity_categories(json.loads(line)["text"], self.cls):
                        sev[SEV_LABELS[c]] = sev.get(SEV_LABELS[c], 0) + 1
        return {
            "class": self.cls, "status": self.status, "note": self.note,
            "seed_count": len(self.seeds), "real": self.real,
            "kept": self.kept, "batches": self.batches,
            "candidates_seen": self.seen_total,
            "rejection_rate": round(self.rejection_rate, 4),
            "rejections": dict(sorted(self.rejections.items(), key=lambda kv: -kv[1])),
            "rejections_by_gate": gs.by_gate(self.rejections),
            "severity_mix": dict(sorted(sev.items(), key=lambda kv: -kv[1])),
            "ollama_errors": self.errors,
            "elapsed_sec": round(self.elapsed, 1),
            "output": self._display_path(),
        }


_stop = {"flag": False}


def _handle_stop(signum, frame):
    _stop["flag"] = True
    log("signal %s received -- finishing current batch, then checkpointing" % signum)


def run(classes: list, blocked: dict, target: int, batch: int,
        budget_hours: float) -> dict:
    SYNTH.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    t_start = time.time()
    deadline = t_start + budget_hours * 3600
    started = now()

    seen = gs.corpus_hashes()
    log("corpus dedupe set: %d hashes from data/processed/" % len(seen))

    states = {c: ClassState(c, seen) for c in classes}
    active = [c for c in classes if states[c].kept < target]
    for c in classes:
        if c not in active:
            states[c].status = "TARGET_REACHED"

    def checkpoint(run_status: str) -> dict:
        out = {
            "run_status": run_status,
            "started_utc": started, "updated_utc": now(),
            "elapsed_sec": round(time.time() - t_start, 1),
            "budget_hours": budget_hours,
            "target_per_class": target, "batch_size": batch,
            "model": gs.MODEL, "ollama": gs.OLLAMA,
            "total_kept": sum(s.kept for s in states.values()),
            "classes_not_ready": blocked,
            "classes": [states[c].summary() for c in classes],
        }
        atomic_write_json(STATUS, out)
        return out

    log("START budget=%sh target=%d/class batch=%d classes=%d model=%s"
        % (budget_hours, target, batch, len(active), gs.MODEL))
    for c, why in blocked.items():
        log("  NOT_READY %s: %s" % (c, why))
    checkpoint("RUNNING")

    while active and not _stop["flag"] and time.time() < deadline:
        for cls in list(active):
            if _stop["flag"] or time.time() >= deadline:
                break
            st = states[cls]
            t0 = time.time()
            try:
                cands = gs.ollama_generate(cls, st.seeds, batch, st.rng)
                st.consecutive_errors = 0
            except TRANSIENT_ERRORS as e:
                st.errors += 1
                st.consecutive_errors += 1
                st.elapsed += time.time() - t0
                log("  %s: OLLAMA error (%d) %s: %s"
                    % (cls, st.consecutive_errors, type(e).__name__, str(e)[:160]))
                if st.consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    st.status = "OLLAMA_ERROR"
                    st.note = "%d consecutive Ollama failures" % MAX_CONSECUTIVE_ERRORS
                    active.remove(cls)
                    log("  %s: DEACTIVATED -- %s" % (cls, st.note))
                checkpoint("RUNNING")
                continue

            st.batches += 1
            newly = []
            for c in cands:
                ok, why = gs.accept(c, cls, seen, st.token_pool)
                if ok:
                    seen.add(gs._hash(c))
                    st.token_pool.append(gs._tokens(c))
                    newly.append(c)
                    st.kept += 1
                    if st.kept >= target:
                        break
                else:
                    st.rejections[why] = st.rejections.get(why, 0) + 1
            if newly:
                st.append(newly)
            st.elapsed += time.time() - t0

            log("  %s: batch %d +%d -> %d/%d (rej %.0f%%, %.0fs)"
                % (cls, st.batches, len(newly), st.kept, target,
                   st.rejection_rate * 100, time.time() - t0))

            if st.kept >= target:
                st.status = "TARGET_REACHED"
                active.remove(cls)
                log("  %s: TARGET_REACHED at %d" % (cls, st.kept))
            elif (st.seen_total >= MIN_SEEN_BEFORE_SKIP
                  and st.rejection_rate > SKIP_REJECTION_RATE):
                st.status = "SKIPPED_HIGH_REJECTION"
                st.note = ("rejection %.1f%% > %.0f%% after %d candidates"
                           % (st.rejection_rate * 100, SKIP_REJECTION_RATE * 100,
                              st.seen_total))
                active.remove(cls)
                log("  %s: SKIPPED -- %s" % (cls, st.note))
            checkpoint("RUNNING")

    if _stop["flag"]:
        final = "STOPPED_BY_SIGNAL"
    elif not active:
        final = "ALL_CLASSES_SETTLED"
    else:
        final = "BUDGET_EXHAUSTED"
        for c in active:
            states[c].status = "BUDGET_EXHAUSTED"
    out = checkpoint(final)
    log("END %s total_kept=%d elapsed=%.2fh"
        % (final, out["total_kept"], out["elapsed_sec"] / 3600))
    for s in out["classes"]:
        log("  %-32s %-24s kept=%-5d rej=%.0f%%"
            % (s["class"], s["status"], s["kept"], s["rejection_rate"] * 100))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", default="", help="comma-separated; default = all ready")
    ap.add_argument("--target", type=int, default=gs.FLOOR, help="kept rows per class")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--budget-hours", type=float, default=8.0)
    args = ap.parse_args()

    ready, blocked = ready_classes()
    if args.classes:
        want = [c.strip() for c in args.classes.split(",") if c.strip()]
        unknown = [c for c in want if c not in ready]
        if unknown:
            ap.error("not ready for generation: %s (ready: %s)" % (unknown, ready))
        ready = want
    if not ready:
        ap.error("no class has both a CLASS_SPEC and hand-written seeds")
    run(ready, blocked, args.target, args.batch, args.budget_hours)


if __name__ == "__main__":
    main()
