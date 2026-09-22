"""SQLite audit log of pipeline verdicts.

The DB path defaults to audit/trishul_audit.db and can be overridden with the
TRISHUL_AUDIT_DB env var (tests point it at a temp file). The table is created
on first use. Seeded demo-history rows carry seeded=1 so they are always
distinguishable from real simulate writes.
"""
from __future__ import annotations

import json
import os
import random
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent / "trishul_audit.db"
SEED_TARGET = 25

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    attack_id        TEXT    NOT NULL,
    tool_name        TEXT    NOT NULL,
    is_attack        INTEGER NOT NULL,
    decision         TEXT    NOT NULL,
    blocked_at_layer TEXT,
    total_latency_ms REAL    NOT NULL,
    reason           TEXT    NOT NULL,
    trace_json       TEXT    NOT NULL,
    seeded           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_verdicts_ts ON verdicts(timestamp);
"""
_LIST_COLS = ("id, timestamp, attack_id, tool_name, is_attack, decision, "
              "blocked_at_layer, total_latency_ms, reason, seeded")


def db_path() -> Path:
    return Path(os.environ.get("TRISHUL_AUDIT_DB", DEFAULT_DB))


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write_verdict(*, timestamp: str, attack_id: str, tool_name: str, is_attack: bool,
                  decision: str, blocked_at_layer: str | None, total_latency_ms: float,
                  reason: str, trace: list[dict], seeded: bool = False) -> int:
    with closing(_connect()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO verdicts (timestamp, attack_id, tool_name, is_attack, decision, "
            "blocked_at_layer, total_latency_ms, reason, trace_json, seeded) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, attack_id, tool_name, int(is_attack), decision, blocked_at_layer,
             total_latency_ms, reason, json.dumps(trace, ensure_ascii=False), int(seeded)),
        )
        return cur.lastrowid


def list_verdicts(limit: int = 25, offset: int = 0) -> tuple[list[dict], int]:
    with closing(_connect()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        rows = conn.execute(
            f"SELECT {_LIST_COLS} FROM verdicts ORDER BY timestamp DESC, id DESC "
            "LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["is_attack"] = bool(d["is_attack"])
        d["seeded"] = bool(d["seeded"])
        items.append(d)
    return items, total


def metrics() -> dict:
    with closing(_connect()) as conn:
        total, blocks, allows, avg_latency = conn.execute(
            "SELECT COUNT(*), "
            "COALESCE(SUM(decision = 'BLOCK'), 0), "
            "COALESCE(SUM(decision = 'ALLOW'), 0), "
            "COALESCE(AVG(total_latency_ms), 0) FROM verdicts").fetchone()
        attacks, attacks_allowed = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(decision = 'ALLOW'), 0) "
            "FROM verdicts WHERE is_attack = 1").fetchone()
        traces = [r[0] for r in conn.execute("SELECT trace_json FROM verdicts")]

    per_layer: dict[str, dict] = {}
    for tj in traces:
        for lr in json.loads(tj):
            s = per_layer.setdefault(lr["layer"], {"inspected": 0, "blocks": 0, "_lat": 0.0})
            s["inspected"] += 1
            s["blocks"] += lr["verdict"] == "BLOCK"
            s["_lat"] += lr["latency_ms"]
    for s in per_layer.values():
        s["avg_latency_ms"] = round(s.pop("_lat") / s["inspected"], 3)

    return {
        "total_requests": total,
        "blocks": blocks,
        "allows": allows,
        "attack_success_rate": round(attacks_allowed / attacks, 4) if attacks else 0.0,
        "avg_latency_ms": round(avg_latency, 3),
        "per_layer_stats": dict(sorted(per_layer.items())),
    }


# ---------------------------------------------------------------- demo seeding

ROT13_REASON = ("novel encoding caught by AI judge on semantic reasoning; "
                "Layers 1.5 and 2a passed it")

_SEED_ATTACKS = [  # (attack_id, tool_name, blocked_at_layer, why)
    ("unicode_tag_credential_exfil", "sentry.get_error_logs", "1.5", "hidden tag-block instruction"),
    ("homoglyph_injection", "github.get_issue", "1.5", "homoglyph-obfuscated instruction"),
    ("novel_encoding_rot13", "docs.get_page", "4", ROT13_REASON),
    ("prompt_injection_blocked", "web.fetch", "2a", "known injection phrase"),
    ("phishing_url_blocked", "email.read_inbox", "2a", "attacker-controlled URL"),
    ("rug_pull_calendar", "calendar.get_events", "5", "tool description changed after approval"),
    ("pii_leak_blocked", "crm.lookup_customer", "4", "judge flagged PII harvesting"),
]
_SEED_ALLOWS = [
    ("credential_scan_ok", "vault.list_paths"),
    ("readme_fetch_ok", "github.get_readme"),
]
_LAYER_NAMES = {"5": "Schema Drift", "1.5": "Normalize", "2a": "Patterns", "4": "Judge"}


def _seed_trace(rng: random.Random, total_ms: float, blocked_at: str | None) -> list[dict]:
    # Layer 5 runs first (request side); a Layer 5 BLOCK means nothing else ran.
    if blocked_at == "5":
        return [{"layer": "5", "name": "Schema Drift", "verdict": "BLOCK",
                 "latency_ms": total_ms, "input_text": "", "output_text": "",
                 "reasoning": None, "details": {"seeded": True}}]
    layers = ["5", "1.5", "2a", "4"]
    lat = {"5": rng.uniform(0.3, 2.0), "1.5": rng.uniform(0.1, 0.9), "2a": rng.uniform(0.05, 1.5)}
    lat["4"] = total_ms - sum(lat[l] for l in layers if l != "4")
    return [{
        "layer": l, "name": _LAYER_NAMES[l],
        "verdict": "BLOCK" if l == blocked_at else "ALLOW",
        "latency_ms": round(lat[l], 3),
        "input_text": "", "output_text": "", "reasoning": None,
        "details": {"seeded": True},
    } for l in layers]


def seed_rows(now: datetime | None = None) -> list[dict]:
    """25 deterministic demo-history rows over the past 24h: 18 attacks
    (all BLOCK; 3 are novel_encoding_rot13 caught only at Layer 4) and 7 benign
    ALLOW."""
    now = now or datetime.now(timezone.utc)
    rng = random.Random(1337)
    kinds = ([("ATTACK", _SEED_ATTACKS[i % len(_SEED_ATTACKS)]) for i in range(18)]
             + [("ALLOW", _SEED_ALLOWS[i % len(_SEED_ALLOWS)]) for i in range(7)])
    rng.shuffle(kinds)
    rows = []
    slot = timedelta(hours=24) / SEED_TARGET
    for i, (kind, spec) in enumerate(kinds):
        ts = now - slot * (i + 0.5) + timedelta(minutes=rng.uniform(-20, 20))
        schema_only = kind == "ATTACK" and spec[2] == "5"
        total_ms = round(rng.uniform(0.5, 3.0) if schema_only else rng.uniform(30, 1200), 1)
        if kind == "ATTACK":
            attack_id, tool, layer, why = spec
            decision, reason = "BLOCK", f"Blocked at Layer {layer}: {why}"
        else:
            (attack_id, tool), layer = spec, None
            decision, reason = "ALLOW", "All layers passed"
        rows.append(dict(timestamp=utc_iso(ts), attack_id=attack_id, tool_name=tool,
                         is_attack=kind == "ATTACK", decision=decision,
                         blocked_at_layer=layer, total_latency_ms=total_ms, reason=reason,
                         trace=_seed_trace(rng, total_ms, layer), seeded=True))
    return rows


def seed_if_needed() -> int:
    """Insert demo history once. Idempotent: skips if any seeded row exists."""
    with closing(_connect()) as conn:
        already = conn.execute("SELECT COUNT(*) FROM verdicts WHERE seeded = 1").fetchone()[0]
    if already:
        return 0
    rows = seed_rows()
    for r in rows:
        write_verdict(**r)
    return len(rows)
