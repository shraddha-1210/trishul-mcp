"""Trishul demo backend. Run: uvicorn backend.main:app --port 8002"""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from attacks.catalog import ATTACKS
from attacks.manifests import APPROVED, custom_manifest
from audit import db
from policy import engine as policy
from workers.layer4_judges import layer as judge_layer
from workers.layer5_schema import layer as schema_layer
from backend import mcp_client
from backend.pipeline import ToolContext, run_layers
from backend.schemas import (AttackInfo, AuditPage, Metrics, SimulateRequest,
                             SimulateResponse)

log = logging.getLogger("trishul.backend")


class LiveHub:
    """Fan-out of pipeline events to every connected /ws/live client."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except (WebSocketDisconnect, RuntimeError) as e:
                # A client that went away must not fail the simulation for others.
                log.warning("dropping /ws/live client: %r", e)
                self.disconnect(ws)


hub = LiveHub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    inserted = db.seed_if_needed()
    log.warning("audit db %s: seeded %d demo-history rows", db.db_path(), inserted)
    # Operator approval of the connected tools' manifests (Layer 5 snapshots). Raises
    # if the snapshot store is unusable: without snapshots every call would drift-check
    # against nothing, so refuse to start.
    for tool_name, manifest in APPROVED.items():
        schema_layer.approve(tool_name, manifest)
    log.warning("schema store %s: approved %d tool manifests", schema_layer.db_path(), len(APPROVED))
    # The mock MCP server is not required to start (custom text still works), but
    # without it every catalog attack returns 502, so say so loudly.
    try:
        await mcp_client.fetch_manifest(next(iter(APPROVED)))
        log.warning("mock MCP server reachable at %s", mcp_client.server_url())
    except mcp_client.ToolServerError as e:
        log.error("mock MCP server NOT reachable (%s): catalog attacks will return 502", e)
    # Preload the judge model so no demo request pays the ~16 s cold load inside
    # the judge's 15 s budget. If Ollama is down the server still starts; every
    # judge call then fails closed to BLOCK with error "judge_unavailable".
    try:
        secs = await run_in_threadpool(judge_layer.warmup)
        log.warning("judge model %s loaded in %.1fs", judge_layer.MODEL, secs)
    except httpx.HTTPError as e:
        log.error("judge warmup FAILED (%r): Layer 4 will fail closed to BLOCK", e)
    yield


app = FastAPI(title="Trishul", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/attacks", response_model=list[AttackInfo])
def list_attacks():
    return [AttackInfo(id=a.id, name=a.name, description=a.description, severity=a.severity,
                       tool_name=a.tool_name, status=a.status) for a in ATTACKS.values()]


@app.post("/api/simulate", response_model=SimulateResponse)
async def simulate(req: SimulateRequest):
    """Live mode (catalog attack, no attack_text): fetch the tool's manifest from the
    MCP server, run Layer 5, and only then forward the call and inspect the real
    response. Custom mode (attack_text given): no server involved; the text is
    inspected as if it were the tool response."""
    attack = ATTACKS.get(req.attack_id)
    if attack is None and req.attack_text is None:
        raise HTTPException(404, f"unknown attack_id {req.attack_id!r} and no attack_text given")
    tool_name = attack.tool_name if attack else "custom"
    run_id = uuid.uuid4().hex[:12]
    timestamp = db.utc_iso(datetime.now(timezone.utc))
    mcp_ms = 0.0

    if req.attack_text is None:
        source = "mcp"
        try:
            manifest, mcp_ms = await mcp_client.fetch_manifest(tool_name)
        except mcp_client.ToolServerError as e:
            raise HTTPException(502, str(e)) from e

        async def fetch_response() -> str:
            nonlocal mcp_ms
            text, ms = await mcp_client.call_tool(tool_name, attack.call_args)
            mcp_ms += ms
            return text
    else:
        source = "custom_text"
        manifest = attack.manifest if attack else custom_manifest(
            "Unknown tool (custom text submitted to the simulator).")

        async def fetch_response() -> str:
            return req.attack_text

    ctx = ToolContext(tool_name=tool_name, tool_description=manifest["description"],
                      manifest=manifest)
    t0 = time.perf_counter()
    try:
        run = await run_layers(ctx, fetch_response, source=source, run_id=run_id,
                               attack_id=req.attack_id, emit=hub.broadcast)
    except mcp_client.ToolServerError as e:
        raise HTTPException(502, str(e)) from e
    # Trishul's own time: wall clock minus waiting on the upstream tool.
    total_ms = round((time.perf_counter() - t0) * 1000 - (run.tool_call_ms or 0.0), 3)
    trace = run.trace
    verdict = policy.decide(trace)
    decision, blocked_at, reason = verdict.decision, verdict.blocked_at_layer, verdict.reason

    audit_id = db.write_verdict(
        timestamp=timestamp, attack_id=req.attack_id, tool_name=tool_name,
        is_attack=attack is not None, decision=decision, blocked_at_layer=blocked_at,
        total_latency_ms=total_ms, reason=reason,
        trace=[lr.model_dump() for lr in trace],
    )
    await hub.broadcast({"event": "verdict", "run_id": run_id, "attack_id": req.attack_id,
                         "final_verdict": decision, "blocked_at_layer": blocked_at,
                         "reason": reason, "total_latency_ms": total_ms, "audit_id": audit_id})
    return SimulateResponse(trace=trace, final_verdict=decision, reason=reason,
                            total_latency_ms=total_ms, blocked_at_layer=blocked_at,
                            attack_id=req.attack_id, tool_name=tool_name,
                            timestamp=timestamp, audit_id=audit_id, source=source,
                            forwarded=run.tool_call_ms is not None,
                            mcp_latency_ms=round(mcp_ms, 3) if source == "mcp" else None)


@app.get("/api/audit", response_model=AuditPage)
def audit(limit: int = Query(25, ge=1, le=500), offset: int = Query(0, ge=0)):
    items, total = db.list_verdicts(limit, offset)
    return AuditPage(items=items, total=total, limit=limit, offset=offset)


@app.get("/api/metrics", response_model=Metrics)
def metrics():
    return db.metrics()


@app.websocket("/ws/live")
async def live(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()  # clients don't send; this just detects disconnect
    except WebSocketDisconnect:
        hub.disconnect(ws)
