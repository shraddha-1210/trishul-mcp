"""Pydantic request/response models for the Trishul demo API."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SimulateRequest(BaseModel):
    attack_id: str
    attack_text: str | None = None


class LayerResult(BaseModel):
    layer: str  # "1.5", "2a", "4", ...
    name: str
    verdict: Literal["ALLOW", "BLOCK"]
    latency_ms: float
    input_text: str
    output_text: str
    reasoning: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class SimulateResponse(BaseModel):
    trace: list[LayerResult]
    final_verdict: Literal["ALLOW", "BLOCK"]
    reason: str
    total_latency_ms: float
    blocked_at_layer: str | None
    attack_id: str
    tool_name: str
    timestamp: str
    audit_id: int
    source: Literal["mcp", "custom_text"]  # mcp: response fetched live from the mock MCP server
    forwarded: bool  # False when a request-side layer blocked the call before forwarding
    mcp_latency_ms: float | None  # tools/list + tools/call round trips; None for custom_text


class AttackInfo(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    tool_name: str
    status: str


class AuditRow(BaseModel):
    id: int
    timestamp: str
    attack_id: str
    tool_name: str
    is_attack: bool
    decision: str
    blocked_at_layer: str | None
    total_latency_ms: float
    reason: str
    seeded: bool


class AuditPage(BaseModel):
    items: list[AuditRow]
    total: int
    limit: int
    offset: int


class LayerStats(BaseModel):
    inspected: int
    blocks: int
    avg_latency_ms: float


class Metrics(BaseModel):
    total_requests: int
    blocks: int
    allows: int
    attack_success_rate: float
    avg_latency_ms: float
    per_layer_stats: dict[str, LayerStats]
