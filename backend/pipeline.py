"""Inspection pipeline: runs the layers in order and emits live events.

Layer 5 (request side: is the tool manifest still the approved one?) ->
Layer 1.5 -> Layer 2a -> Layer 4 (response side; judge always runs for the demo).
The final ALLOW/BLOCK is made by policy/engine.py from the returned trace.

The tool response is fetched (the call is "forwarded") only after Layer 5
passes, and a tool_call event marks that moment. A Layer 5 BLOCK stops the run:
the call is never forwarded, so there is no response to inspect. The skipped
layers get a layer_skipped event.

Layers run in a worker thread (the judge blocks ~8 s on CPU) so the event loop
keeps streaming /ws/live events while a simulation is in flight.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from starlette.concurrency import run_in_threadpool

from backend.schemas import LayerResult
from workers.layer1_5_normalize.layer import NormalizationError, normalize
from workers.layer2a_patterns.layer import PatternScanError, scan
from workers.layer4_judges.layer import MODEL as JUDGE_MODEL
from workers.layer4_judges.layer import judge
from workers.layer5_schema import layer as schema

Emit = Callable[[dict], Awaitable[None]]
FetchResponse = Callable[[], Awaitable[str]]
REQUEST_SIDE = frozenset({"5"})  # inspect the call/manifest; don't transform the response


@dataclass(frozen=True)
class ToolContext:
    tool_name: str
    tool_description: str
    manifest: dict  # manifest served at call time


def run_layer_5(text: str, ctx: ToolContext) -> LayerResult:
    # Inspects the manifest, not the response: input/output are the live manifest.
    # The response is never touched here (it may not even be valid UTF-8 yet).
    c = schema.check(ctx.tool_name, ctx.manifest)
    if c.status == "drift":
        reasoning = f"Schema drift since approval: {c.summary}"
    elif c.status == "store_error":
        reasoning = f"Fail-closed: {c.error}"
    elif c.status == "first_sight":
        reasoning = "First sight of this tool: snapshot recorded (trust on first use)"
    elif c.status == "cosmetic":
        reasoning = "Manifest matches approved snapshot (whitespace-only difference ignored)"
    else:
        reasoning = "Manifest matches approved snapshot"
    manifest_json = json.dumps(ctx.manifest, indent=2, ensure_ascii=False)
    return LayerResult(
        layer="5", name="Schema Drift", verdict=c.verdict,
        latency_ms=round(c.latency_ms, 3),
        input_text=manifest_json, output_text=manifest_json, reasoning=reasoning,
        details={
            "status": c.status,
            "reason": {"drift": "schema_drift", "store_error": "schema_store_unavailable"}
                      .get(c.status),
            "error": c.error and "schema_store_unavailable",
            "tool_name": c.tool_name,
            "live_hash": c.live_hash,
            "approved_hash": c.approved_hash,
            "approved_at": c.approved_at,
            "field_count": c.field_count,
            "changes": [{"path": ch.path, "kind": ch.kind, "old": ch.old, "new": ch.new,
                         "summary": ch.describe()} for ch in c.changes],
            "approved_manifest": c.approved_manifest,
            "live_manifest": ctx.manifest,
        },
    )


def run_layer_1_5(text: str) -> LayerResult:
    # Demo policy: obfuscation is treated as BLOCK at Layer 1.5, so attacks 1 and 2
    # report blocked_at_layer "1.5". (implementation.md §3.2 has it as a signal only.)
    try:
        n = normalize(text)
    except NormalizationError as e:
        # Undecodable text can't be JSON-encoded or stored as-is: keep an escaped copy.
        safe = text.encode("utf-8", "backslashreplace").decode("utf-8")
        return LayerResult(
            layer="1.5", name="Normalize", verdict="BLOCK", latency_ms=0.0,
            input_text=safe, output_text="",
            reasoning=f"Fail-closed: {e.reason}", details={"error": e.reason},
        )
    if n.was_obfuscated:
        parts = [f"{t}" for t in n.stripped_types] or ["base64_non_ascii"]
        reasoning = f"Obfuscation detected ({', '.join(parts)})"
        if n.stripped_chars_count:
            reasoning += f"; {n.stripped_chars_count} invisible chars stripped"
        if n.homoglyph_count:
            reasoning += f"; {n.homoglyph_count} homoglyphs folded to Latin"
        if n.hidden_text:
            reasoning += "; hidden instruction revealed"
    else:
        reasoning = "No obfuscation detected"
    return LayerResult(
        layer="1.5", name="Normalize",
        verdict="BLOCK" if n.was_obfuscated else "ALLOW",
        latency_ms=round(n.latency_ms, 3),
        input_text=text, output_text=n.canonical_text, reasoning=reasoning,
        details={
            "was_obfuscated": n.was_obfuscated,
            "stripped_chars_count": n.stripped_chars_count,
            "stripped_types": n.stripped_types,
            "homoglyph_count": n.homoglyph_count,
            "hidden_text": n.hidden_text,
            "transformations": n.transformations,
        },
    )


def run_layer_2a(text: str) -> LayerResult:
    try:
        s = scan(text)
    except PatternScanError as e:
        return LayerResult(
            layer="2a", name="Patterns", verdict="BLOCK", latency_ms=0.0,
            input_text=text, output_text=text,
            reasoning=f"Fail-closed: {e}", details={"error": "scan_error"},
        )
    if s.matched:
        reasoning = (f"Matched {len(s.matched_patterns)} known-attack pattern(s) "
                     f"[{', '.join(s.categories)}]: " + ", ".join(repr(p) for p in s.matched_patterns))
    else:
        reasoning = "No known-attack patterns matched"
    return LayerResult(
        layer="2a", name="Patterns",
        verdict="BLOCK" if s.matched else "ALLOW",
        latency_ms=round(s.latency_ms, 3),
        input_text=text, output_text=text, reasoning=reasoning,
        details={
            "matched": s.matched,
            "matched_spans": s.matched_spans,
            "matched_patterns": s.matched_patterns,
            "matched_text": [text[a:b] for a, b in s.matched_spans],
            "categories": s.categories,
        },
    )


def run_layer_4(text: str, ctx: ToolContext) -> LayerResult:
    j = judge(text, ctx.tool_name, ctx.tool_description)
    return LayerResult(
        layer="4", name="Judge", verdict=j.verdict,
        latency_ms=round(j.latency_ms, 3),
        input_text=text, output_text=text, reasoning=j.reasoning,
        details={
            "confidence": j.confidence,
            "model": JUDGE_MODEL,
            "error": j.error,
            "raw_response": j.raw_response,
        },
    )


LAYERS: list[tuple[str, str, Callable[[str, ToolContext], LayerResult]]] = [
    ("5", "Schema Drift", run_layer_5),
    ("1.5", "Normalize", lambda text, ctx: run_layer_1_5(text)),
    ("2a", "Patterns", lambda text, ctx: run_layer_2a(text)),
    ("4", "Judge", run_layer_4),
]


@dataclass
class Run:
    trace: list[LayerResult]
    tool_call_ms: float | None  # time spent fetching the tool response; None if never forwarded


async def run_layers(ctx: ToolContext, fetch_response: FetchResponse, *, source: str,
                     run_id: str, attack_id: str, emit: Emit) -> Run:
    """Run the cascade. fetch_response() is awaited only once every request-side
    layer has passed, i.e. this is the moment the call is forwarded to the tool."""
    trace: list[LayerResult] = []
    current: str | None = None
    tool_call_ms: float | None = None
    for i, (layer_id, name, fn) in enumerate(LAYERS):
        if layer_id not in REQUEST_SIDE and current is None:
            t0 = time.perf_counter()
            try:
                current = await fetch_response()
            except Exception as e:
                await emit({"event": "run_error", "run_id": run_id, "attack_id": attack_id,
                            "error": str(e)})
                raise
            tool_call_ms = round((time.perf_counter() - t0) * 1000, 3)
            await emit({"event": "tool_call", "tool_name": ctx.tool_name, "source": source,
                        "run_id": run_id, "attack_id": attack_id, "latency_ms": tool_call_ms})
        await emit({"event": "layer_start", "layer": layer_id, "name": name,
                    "run_id": run_id, "attack_id": attack_id})
        result = await run_in_threadpool(fn, current or "", ctx)
        trace.append(result)
        await emit({"event": "layer_complete", "layer": layer_id, "name": name,
                    "run_id": run_id, "attack_id": attack_id, "verdict": result.verdict,
                    "latency_ms": result.latency_ms, "reasoning": result.reasoning})
        stop = None
        if layer_id == "5" and result.verdict == "BLOCK":
            stop = "call blocked before forwarding: no tool response to inspect"
        elif layer_id == "1.5" and result.details.get("error"):
            stop = "fail-closed: nothing downstream can inspect undecodable input"
        if stop:
            for skipped_id, skipped_name, _ in LAYERS[i + 1:]:
                await emit({"event": "layer_skipped", "layer": skipped_id, "name": skipped_name,
                            "run_id": run_id, "attack_id": attack_id, "reason": stop})
            break
        if layer_id not in REQUEST_SIDE:
            current = result.output_text  # later layers see canonical text
    return Run(trace=trace, tool_call_ms=tool_call_ms)
