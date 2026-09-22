"""Policy engine unit tests. Pure function over real LayerResult objects; no mocks."""
from __future__ import annotations

from backend.schemas import LayerResult
from policy.engine import decide

NAMES = {"5": "Schema Drift", "1.5": "Normalize", "2a": "Patterns", "4": "Judge"}


def lr(layer: str, verdict: str, reasoning: str = "r", **details) -> LayerResult:
    return LayerResult(layer=layer, name=NAMES[layer], verdict=verdict, latency_ms=1.0,
                       input_text="t", output_text="t", reasoning=reasoning, details=details)


def ok(*layers: str) -> list[LayerResult]:
    return [lr(l, "ALLOW") for l in layers]


def test_all_allow_is_allow():
    d = decide(ok("5", "1.5", "2a", "4"))
    assert (d.decision, d.blocked_at_layer, d.reason) == ("ALLOW", None, "All layers passed")


def test_single_block_anywhere_is_block_at_that_layer():
    for i, layer in enumerate(NAMES):
        trace = [lr(l, "BLOCK" if j == i else "ALLOW", f"why-{l}") for j, l in enumerate(NAMES)]
        d = decide(trace)
        assert (d.decision, d.blocked_at_layer) == ("BLOCK", layer)
        assert d.reason.startswith(f"Blocked at Layer {layer} ({NAMES[layer]})")
        assert d.reason.endswith(f": why-{layer}")


def test_earliest_block_wins_even_if_later_layers_allow_or_block():
    d = decide(ok("5", "1.5") + [lr("2a", "BLOCK", "pattern"), lr("4", "BLOCK", "judge")])
    assert d.blocked_at_layer == "2a" and d.reason.endswith(": pattern")
    d = decide(ok("5") + [lr("1.5", "BLOCK", "obf")] + ok("2a", "4"))
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", "1.5")  # later ALLOWs can't override


def test_judge_only_catch_is_labelled_semantic():
    # The Attack 3 shape: both deterministic layers pass, the judge blocks on intent.
    d = decide(ok("5", "1.5", "2a") + [lr("4", "BLOCK", "encoded instruction")])
    assert d.blocked_at_layer == "4"
    assert d.reason == ("Blocked at Layer 4 (Judge), deterministic layers 1.5 and 2a passed; "
                        "caught on semantic reasoning: encoded instruction")


def test_judge_fail_closed_is_not_labelled_semantic():
    d = decide(ok("5", "1.5", "2a")
               + [lr("4", "BLOCK", "Fail-closed (judge_timeout): no answer", error="judge_timeout")])
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", "4")
    assert "semantic" not in d.reason
    assert d.reason == "Blocked at Layer 4 (Judge): Fail-closed (judge_timeout): no answer"


def test_deterministic_block_is_not_labelled_semantic():
    d = decide(ok("5", "1.5") + [lr("2a", "BLOCK", "p"), lr("4", "BLOCK", "j")])
    assert "semantic" not in d.reason


def test_schema_drift_block_alone_is_block_at_5():
    # Rug pull: Layer 5 blocks request-side, so the response layers never run.
    d = decide([lr("5", "BLOCK", "Schema drift since approval: tool description changed")])
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", "5")
    assert d.reason == ("Blocked at Layer 5 (Schema Drift): "
                        "Schema drift since approval: tool description changed")


def test_decision_is_only_ever_allow_or_block():
    traces = [[lr("5", w), lr("1.5", a), lr("2a", b), lr("4", c)]
              for w in ("ALLOW", "BLOCK") for a in ("ALLOW", "BLOCK")
              for b in ("ALLOW", "BLOCK") for c in ("ALLOW", "BLOCK")]
    decisions = [decide(t).decision for t in traces]
    assert set(decisions) == {"ALLOW", "BLOCK"}
    assert decisions.count("ALLOW") == 1  # only all-ALLOW allows


# ---------------------------------------------------------------- fail-closed

def test_empty_trace_fails_closed():
    d = decide([])
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", None)
    assert d.reason == "Fail-closed: no layers ran"


def test_missing_required_layer_fails_closed():
    d = decide(ok("5", "1.5", "2a"))  # judge never ran
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", None)
    assert d.reason == "Fail-closed: required layer(s) 4 did not run"
    d = decide(ok("1.5", "2a", "4"))  # schema check never ran
    assert d.decision == "BLOCK" and d.reason == "Fail-closed: required layer(s) 5 did not run"


def test_truncated_trace_with_block_still_reports_the_block():
    # Pipeline stops after an L1.5 decode error; the block is the reason, not the missing layers.
    d = decide(ok("5") + [lr("1.5", "BLOCK", "Fail-closed: encoding_error", error="encoding_error")])
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", "1.5")
    assert d.reason == "Blocked at Layer 1.5 (Normalize): Fail-closed: encoding_error"


def test_unknown_verdict_fails_closed():
    # schemas.LayerResult forbids this; model_construct bypasses validation to prove the
    # engine doesn't rely on it.
    bad = LayerResult.model_construct(layer="2a", name="Patterns", verdict="AMBER", latency_ms=1.0,
                                      input_text="", output_text="", reasoning="x", details={})
    d = decide(ok("5", "1.5") + [bad] + ok("4"))
    assert (d.decision, d.blocked_at_layer) == ("BLOCK", "2a")
    assert d.reason == "Fail-closed: Layer 2a returned unknown verdict 'AMBER'"


def test_custom_required_layers():
    assert decide([lr("1.5", "ALLOW")], required_layers=("1.5",)).decision == "ALLOW"
