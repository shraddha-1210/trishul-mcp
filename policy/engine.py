"""Policy engine: turns the per-layer trace into one final ALLOW/BLOCK.

The rule is deliberately simple and has no AMBER / human-review lane:
  - any layer BLOCK  -> BLOCK, blocked_at_layer = earliest blocking layer
  - every required layer ALLOW -> ALLOW
Fails closed: an empty trace, a missing required layer, or a verdict other
than ALLOW/BLOCK yields BLOCK. (implementation.md §3.9 describes the full
ActionPolicy chain + Ed25519 signing; both are out of demo scope.)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from backend.schemas import LayerResult

REQUIRED_LAYERS: tuple[str, ...] = ("5", "1.5", "2a", "4")
DETERMINISTIC_LAYERS: frozenset[str] = frozenset({"1.5", "2a"})


@dataclass(frozen=True)
class PolicyDecision:
    decision: Literal["ALLOW", "BLOCK"]
    blocked_at_layer: str | None
    reason: str


def decide(trace: list[LayerResult],
           required_layers: Iterable[str] = REQUIRED_LAYERS) -> PolicyDecision:
    if not trace:
        return PolicyDecision("BLOCK", None, "Fail-closed: no layers ran")

    for i, lr in enumerate(trace):
        if lr.verdict == "BLOCK":
            return PolicyDecision("BLOCK", lr.layer, _block_reason(lr, trace[:i]))
        if lr.verdict != "ALLOW":
            return PolicyDecision("BLOCK", lr.layer,
                                  f"Fail-closed: Layer {lr.layer} returned unknown verdict {lr.verdict!r}")

    missing = [l for l in required_layers if l not in {lr.layer for lr in trace}]
    if missing:
        return PolicyDecision("BLOCK", None,
                              f"Fail-closed: required layer(s) {', '.join(missing)} did not run")
    return PolicyDecision("ALLOW", None, "All layers passed")


def _block_reason(lr: LayerResult, earlier: list[LayerResult]) -> str:
    head = f"Blocked at Layer {lr.layer} ({lr.name})"
    semantic_only = (lr.layer not in DETERMINISTIC_LAYERS
                     and not lr.details.get("error")
                     and {e.layer for e in earlier} >= DETERMINISTIC_LAYERS)
    if semantic_only:
        # Every deterministic layer passed it; only the judge's reading of intent caught it.
        head += ", deterministic layers 1.5 and 2a passed; caught on semantic reasoning"
    return f"{head}: {lr.reasoning}"
