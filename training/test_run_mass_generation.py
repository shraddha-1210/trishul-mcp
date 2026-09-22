"""Scheduler tests for run_mass_generation.

WHAT IS MOCKED, AND WHY IT IS ALLOWED
-------------------------------------
The unit under test here is the SCHEDULER: round-robin fairness, the >90% skip
rule, checkpoint durability, resume, and Ollama-failure deactivation. The
scheduler's dependency on Ollama is replaced by a deterministic fake generator,
because a real Ollama's output is nondeterministic and cannot pin down "the skip
rule fires at exactly this rejection rate, and not below it".

`gs.accept` / `class_validators.validate` -- the rejection chain -- are NOT
mocked. The fake generator emits real candidate strings and the real validators
judge them. `test_fixtures_behave_as_assumed` proves that up front: if a fixture
stopped passing its own class validator, every ratio-based test below would be
meaningless, so that check runs first and fails loudly.

The real Ollama path is covered separately by the end-to-end smoke run against
the live server, not by this file.

Run: python training/test_run_mass_generation.py
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_synthetic as gs
import run_mass_generation as r

FAILED: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("PASS  %s" % name)
    else:
        FAILED.append(name)
        print("FAIL  %s  %s" % (name, detail))


class Sandbox:
    """Redirect SYNTH output into a temp dir so tests never touch data/synth."""

    def __enter__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="trishul_sched_"))
        self._synth, self._status, self._log = r.SYNTH, r.STATUS, r.LOG
        r.SYNTH = self.tmp
        r.STATUS = self.tmp / "run_status.json"
        r.LOG = self.tmp / "mass_gen.log"
        self._gen = gs.ollama_generate
        r._stop["flag"] = False
        return self

    def __exit__(self, *exc):
        r.SYNTH, r.STATUS, r.LOG = self._synth, self._status, self._log
        gs.ollama_generate = self._gen
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False


# --- fixtures -----------------------------------------------------------------
# One genuinely class-correct tool-response body per class used below. `{tag}` is
# a 4-digit counter that makes every emitted candidate unique, so the dedupe and
# near-dupe filters do not silently turn a "good" candidate into a rejection.

GOOD = {
    "phishing_url_injection": (
        "Mail gateway digest -- 1 quarantined notice (ref {tag})\n\n"
        "From: Microsoft 365 Billing <billing@m365-accounts-renew{tag}.cc>\n"
        "Subject: Storage quota exceeded -- inbound delivery paused\n\n"
        "Your tenant exceeded its mailbox quota and inbound delivery was suspended "
        "on {tag}. Sign in within 24 hours to restore delivery, or queued messages "
        "will be purged: https://m365-accounts-renew{tag}.cc/session/verify"
    ),
    "secret_credential_leak": (
        "GET /v1/config/export?service=billing-api&rev={tag} -> 200 OK\n\n"
        "DATABASE_URL=postgres://billing_svc:Xk7pQ2vLm{tag}@db-prod-3.internal:5432/billing\n"
        "STRIPE_SECRET_KEY=sk_live_51NqAz{tag}BvKmPwRtYuIoPaSdFgHjKlZxCvBnM\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCY{tag}EXAMPLEKEY\n"
        "JWT_SIGNING_SECRET=b3f9c1{tag}d24ae67f0195ab3c8e7d6f4a2\n"
        "REDIS_PASSWORD=r3d1s-pr0d-{tag}-aXmQ"
    ),
    "pii_harvesting": (
        "query: SELECT * FROM members WHERE plan_year = 2026 -- returning row {tag} "
        "of 48120\n\n"
        "member_id: M-{tag}\n"
        "full_name: Marcus Delacroix\n"
        "date_of_birth: 1974-03-11\n"
        "ssn: 412-88-{tag}\n"
        "email: m.delacroix@example.net\n"
        "phone: +1-503-555-{tag}\n"
        "home_address: 88 Larkspur Avenue, Portland, OR 97210\n"
        "diagnosis_code: E11.9 type 2 diabetes mellitus\n"
        "card_on_file: 4539 8812 4471 {tag}\n"
        "annual_salary: 118400.00"
    ),
}

# Rejected by every class validator: no URL, no secret, no PII, no injected
# instruction, no manifest JSON -- just a bland log line.
BAD = "row {tag}: status nominal, queue depth four, nothing further to report today"

CLS = "phishing_url_injection"


def _unique_tail(n: int, width: int = 70) -> str:
    """Tokens unique to candidate `n`, to clear the real near-duplicate filter.

    `gs.accept` rejects anything with token Jaccard >= 0.80 against what came
    before. Two candidates from the same template differing only by a counter sit
    at ~0.99, so without this the fixtures would be rejected as near-duplicates
    and every ratio in these tests would be wrong. This is a property of the REAL
    filter, not something the tests bypass -- the filter still runs.
    """
    ids = " ".join("%x%04xz" % (i, n) for i in range(width))
    return "\n\ndelivery trace ids: " + ids


def fake_generator(good: int, bad: int, cls_good: str = None, tag_start: int = 0):
    """Deterministic stand-in for gs.ollama_generate (see module docstring).

    Emits `good` class-correct candidates and `bad` rejectable ones per call.
    """
    state = {"n": tag_start}

    def gen(cls, seeds, n, rng, timeout=300):
        template = GOOD[cls_good or cls]
        out = []
        for _ in range(good):
            state["n"] += 1
            out.append(template.format(tag="%04d" % state["n"])
                       + _unique_tail(state["n"]))
        for _ in range(bad):
            state["n"] += 1
            out.append(BAD.format(tag="%04d" % state["n"])
                       + _unique_tail(state["n"]))
        return out

    return gen


# --- tests --------------------------------------------------------------------

def test_fixtures_behave_as_assumed():
    """Every ratio test below assumes GOOD passes and BAD fails the REAL validators."""
    for cls, template in GOOD.items():
        ok, why = gs.accept(template.format(tag="9901") + _unique_tail(9901),
                            cls, set(), [])
        check("fixture: GOOD[%s] passes the real validator chain" % cls, ok, why)
    for cls in GOOD:
        ok, why = gs.accept(BAD.format(tag="9902") + _unique_tail(9902),
                            cls, set(), [])
        check("fixture: BAD is rejected for %s" % cls, not ok, "unexpectedly accepted")
    # And the unique tail must actually defeat the near-dupe filter, or every
    # ratio-based test below silently collapses to "kept 1".
    pool = [gs._tokens(GOOD[CLS].format(tag="9901") + _unique_tail(9901))]
    ok, why = gs.accept(GOOD[CLS].format(tag="9903") + _unique_tail(9903),
                        CLS, set(), pool)
    check("fixture: successive candidates are not near-duplicates", ok, why)


def test_happy_path_writes_rows_and_reaches_target():
    with Sandbox():
        gs.ollama_generate = fake_generator(good=4, bad=0)
        out = r.run([CLS], {}, target=6, batch=8, budget_hours=1.0)
        rows = [json.loads(l) for l in
                (r.SYNTH / CLS / "synthetic.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()]
        check("happy: run_status ALL_CLASSES_SETTLED",
              out["run_status"] == "ALL_CLASSES_SETTLED", out["run_status"])
        check("happy: class TARGET_REACHED",
              out["classes"][0]["status"] == "TARGET_REACHED", out["classes"][0]["status"])
        check("happy: exactly target rows on disk", len(rows) == 6, "got %d" % len(rows))
        check("happy: rows carry the right class",
              all(x["trishul_class"] == CLS for x in rows))
        check("happy: rows carry synthetic provenance",
              all(x["source"] == "synthetic" and x["id"].startswith("synthetic_")
                  for x in rows))


def test_high_rejection_class_is_skipped_not_fatal():
    """Owner rule: >90% rejection -> skip THAT class, the run continues."""
    with Sandbox():
        gs.ollama_generate = fake_generator(good=0, bad=10)
        out = r.run([CLS], {}, target=50, batch=10, budget_hours=1.0)
        c = out["classes"][0]
        check("skip: status is SKIPPED_HIGH_REJECTION",
              c["status"] == "SKIPPED_HIGH_REJECTION", c["status"])
        check("skip: rejection rate is 100 percent", c["rejection_rate"] == 1.0,
              str(c["rejection_rate"]))
        check("skip: run settled rather than crashed",
              out["run_status"] == "ALL_CLASSES_SETTLED", out["run_status"])
        check("skip: fired only after the minimum sample",
              c["candidates_seen"] >= r.MIN_SEEN_BEFORE_SKIP, str(c["candidates_seen"]))


def test_skip_does_not_fire_below_the_threshold():
    """NEGATIVE PAIR for the skip rule: a 75 percent-rejection class must SURVIVE.

    Without this, a buggy rule of `rejection_rate > 0` would still pass the test
    above. The calibration probe ran at 77 percent rejection while producing rows
    the owner approved, so an overzealous skip rule would discard good classes.
    """
    with Sandbox():
        gs.ollama_generate = fake_generator(good=2, bad=6)   # 75 percent rejection
        out = r.run([CLS], {}, target=12, batch=8, budget_hours=1.0)
        c = out["classes"][0]
        check("no-skip: 75 percent rejection class was NOT skipped",
              c["status"] != "SKIPPED_HIGH_REJECTION", c["status"])
        check("no-skip: it still reached target",
              c["status"] == "TARGET_REACHED", c["status"])
        check("no-skip: rejection rate is in the 70s",
              0.60 <= c["rejection_rate"] <= 0.85, str(c["rejection_rate"]))


def test_one_bad_class_does_not_stop_the_others():
    with Sandbox():
        good_cls, bad_cls = CLS, "secret_credential_leak"
        good_gen = fake_generator(good=4, bad=0)
        bad_gen = fake_generator(good=0, bad=10)

        def gen(cls, seeds, n, rng, timeout=300):
            return good_gen(cls, seeds, n, rng) if cls == good_cls \
                else bad_gen(cls, seeds, n, rng)
        gs.ollama_generate = gen
        out = r.run([good_cls, bad_cls], {}, target=8, batch=10, budget_hours=1.0)
        by = {c["class"]: c for c in out["classes"]}
        check("isolation: bad class skipped",
              by[bad_cls]["status"] == "SKIPPED_HIGH_REJECTION", by[bad_cls]["status"])
        check("isolation: good class still reached target",
              by[good_cls]["status"] == "TARGET_REACHED", by[good_cls]["status"])
        check("isolation: good class kept all its rows",
              by[good_cls]["kept"] == 8, str(by[good_cls]["kept"]))


def test_round_robin_is_fair():
    """A budget-limited run must spread batches evenly, not drain class 1 first."""
    with Sandbox():
        classes = list(GOOD)
        gs.ollama_generate = fake_generator(good=1, bad=0)
        out = r.run(classes, {}, target=3, batch=8, budget_hours=1.0)
        batches = [c["batches"] for c in out["classes"]]
        kept = [c["kept"] for c in out["classes"]]
        check("fairness: every class got batches", all(b > 0 for b in batches), str(batches))
        check("fairness: batch counts differ by at most 1",
              max(batches) - min(batches) <= 1, str(batches))
        check("fairness: every class reached target", kept == [3, 3, 3], str(kept))


def test_checkpoint_is_written_and_resumable():
    with Sandbox() as sb:
        gs.ollama_generate = fake_generator(good=2, bad=0)
        r.run([CLS], {}, target=4, batch=8, budget_hours=1.0)
        check("checkpoint: status file exists", r.STATUS.exists())
        first = json.loads(r.STATUS.read_text(encoding="utf-8"))
        check("checkpoint: total_kept recorded", first["total_kept"] == 4,
              str(first["total_kept"]))

        # Resume: a second run at a higher target must keep the first run's rows
        # and continue from them -- not restart at zero, not duplicate them.
        gs.ollama_generate = fake_generator(good=2, bad=0, tag_start=5000)
        out2 = r.run([CLS], {}, target=7, batch=8, budget_hours=1.0)
        rows = [json.loads(l) for l in
                (sb.tmp / CLS / "synthetic.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()]
        texts = [x["text"] for x in rows]
        check("resume: continued to the new target", out2["classes"][0]["kept"] == 7,
              str(out2["classes"][0]["kept"]))
        check("resume: rows on disk match", len(rows) == 7, "got %d" % len(rows))
        check("resume: no duplicate text survived", len(set(texts)) == len(texts),
              "%d unique of %d" % (len(set(texts)), len(texts)))


def test_resume_is_a_noop_when_target_already_met():
    with Sandbox():
        gs.ollama_generate = fake_generator(good=2, bad=0)
        r.run([CLS], {}, target=4, batch=8, budget_hours=1.0)

        def explode(*a, **k):
            raise AssertionError("generator called although target was already met")
        gs.ollama_generate = explode
        out = r.run([CLS], {}, target=4, batch=8, budget_hours=1.0)
        check("resume-noop: no generation attempted",
              out["classes"][0]["status"] == "TARGET_REACHED", out["classes"][0]["status"])
        check("resume-noop: kept unchanged", out["total_kept"] == 4, str(out["total_kept"]))


def test_ollama_failure_deactivates_class_after_retries():
    """FAIL-CLOSED: a dead Ollama must not spin forever, nor be silently ignored."""
    with Sandbox():
        calls = {"n": 0}

        def dead(*a, **k):
            calls["n"] += 1
            raise ConnectionError("connection refused")
        gs.ollama_generate = dead
        out = r.run([CLS], {}, target=10, batch=8, budget_hours=1.0)
        c = out["classes"][0]
        check("ollama-fail: class marked OLLAMA_ERROR",
              c["status"] == "OLLAMA_ERROR", c["status"])
        check("ollama-fail: errors counted",
              c["ollama_errors"] == r.MAX_CONSECUTIVE_ERRORS, str(c["ollama_errors"]))
        check("ollama-fail: gave up at the retry cap rather than looping",
              calls["n"] == r.MAX_CONSECUTIVE_ERRORS, str(calls["n"]))
        check("ollama-fail: no rows written", c["kept"] == 0, str(c["kept"]))


def test_unexpected_exception_propagates_not_mislabelled():
    """NEGATIVE PAIR for the error handling above.

    A bug in this codebase (TypeError, AttributeError) must NOT be relabelled as
    "Ollama is unhealthy" and quietly skipped -- that is how a 9-hour unattended
    run produces nothing and reports an innocent-looking status. It must crash.
    """
    with Sandbox():
        def buggy(*a, **k):
            raise TypeError("scheduler bug, not a network problem")
        gs.ollama_generate = buggy
        raised = None
        try:
            r.run([CLS], {}, target=10, batch=8, budget_hours=1.0)
        except TypeError as e:
            raised = e
        check("propagate: TypeError escaped the run loop", raised is not None,
              "run() swallowed it")
        check("propagate: it was not relabelled as OLLAMA_ERROR",
              raised is not None and "scheduler bug" in str(raised), str(raised))


def test_budget_exhaustion_is_reported():
    with Sandbox():
        gs.ollama_generate = fake_generator(good=1, bad=0)
        out = r.run([CLS], {}, target=10_000, batch=8, budget_hours=0.0)
        check("budget: run_status BUDGET_EXHAUSTED",
              out["run_status"] == "BUDGET_EXHAUSTED", out["run_status"])
        check("budget: class marked BUDGET_EXHAUSTED",
              out["classes"][0]["status"] == "BUDGET_EXHAUSTED",
              out["classes"][0]["status"])


def test_not_ready_classes_are_reported_not_hidden():
    ready, blocked = r.ready_classes()
    check("readiness: 10 classes ready", len(ready) == 10, str(len(ready)))
    check("readiness: jailbreak_payload reported as blocked",
          "jailbreak_payload" in blocked, str(list(blocked)))
    check("readiness: every ready class has a spec AND seeds",
          all(c in gs.CLASS_SPECS and gs.load_seeds(c) for c in ready))
    with Sandbox():
        gs.ollama_generate = fake_generator(good=4, bad=0)
        out = r.run([CLS], blocked, target=4, batch=8, budget_hours=1.0)
    check("readiness: blocked classes surface in the checkpoint",
          "jailbreak_payload" in out["classes_not_ready"], str(out["classes_not_ready"]))


def main():
    for fn in (test_fixtures_behave_as_assumed,
               test_happy_path_writes_rows_and_reaches_target,
               test_high_rejection_class_is_skipped_not_fatal,
               test_skip_does_not_fire_below_the_threshold,
               test_one_bad_class_does_not_stop_the_others,
               test_round_robin_is_fair,
               test_checkpoint_is_written_and_resumable,
               test_resume_is_a_noop_when_target_already_met,
               test_ollama_failure_deactivates_class_after_retries,
               test_unexpected_exception_propagates_not_mislabelled,
               test_budget_exhaustion_is_reported,
               test_not_ready_classes_are_reported_not_hidden):
        print("\n== %s ==" % fn.__name__)
        fn()          # deliberately NOT wrapped in try/except: an exception here
                      # is a real failure and must abort with a traceback.
    print("\n" + "-" * 62)
    if FAILED:
        print("FAILED %d of the checks: %s" % (len(FAILED), FAILED))
        sys.exit(1)
    print("ALL SCHEDULER CHECKS PASSED (Ollama stubbed; validators real)")


if __name__ == "__main__":
    main()
