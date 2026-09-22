"""Layer 5 — schema drift / rug-pull detection (implementation.md §3.7).

Compares the tool manifest served at call time against the snapshot the
operator approved. Runs request-side, before the call is forwarded: on drift
the call never reaches the tool, so there is no response for later layers.

- Canonical form: keys sorted, every string whitespace-collapsed. Hash = BLAKE3.
- First sight of a tool: snapshot recorded, ALLOW (trust on first use, per spec).
- Same canonical hash: ALLOW ("match", or "cosmetic" if only whitespace differs).
- Any other change (description, parameters, anything): BLOCK "schema_drift"
  with a structural diff. The snapshot is NOT updated; only approve() does that.
- Snapshot store unreadable/unwritable: BLOCK "schema_store_unavailable".

The store is SQLite at TRISHUL_SCHEMA_DB (default workers/layer5_schema/snapshots.db).
Deviation from spec: a small in-house structural diff replaces the jsondiff dependency.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

import blake3

DEFAULT_DB = Path(__file__).resolve().parent / "snapshots.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_snapshots (
    tool_name      TEXT PRIMARY KEY,
    raw_json       TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    hash           TEXT NOT NULL,
    field_count    INTEGER NOT NULL,
    approved_at    TEXT NOT NULL
);
"""
_UPSERT = (
    "INSERT INTO tool_snapshots (tool_name, raw_json, canonical_json, hash, field_count, "
    "approved_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tool_name) DO UPDATE SET "
    "raw_json=excluded.raw_json, canonical_json=excluded.canonical_json, hash=excluded.hash, "
    "field_count=excluded.field_count, approved_at=excluded.approved_at"
)


def db_path() -> Path:
    return Path(os.environ.get("TRISHUL_SCHEMA_DB", DEFAULT_DB))


@dataclass(frozen=True)
class Change:
    path: str  # dotted, e.g. "inputSchema.properties.sync_token"
    kind: Literal["added", "removed", "changed"]
    old: Any
    new: Any

    def describe(self) -> str:
        parts = self.path.split(".")
        if self.path == "description":
            return "tool description changed"
        if parts[:2] == ["inputSchema", "properties"] and len(parts) >= 3:
            param = parts[2]
            if len(parts) == 3:
                return f"parameter '{param}' {self.kind}"
            if parts[3:] == ["type"] and self.kind == "changed":
                return f"parameter '{param}' type changed ({self.old} -> {self.new})"
            return f"parameter '{param}' {'.'.join(parts[3:])} {self.kind}"
        return f"{self.path} {self.kind}"


@dataclass
class SchemaCheck:
    verdict: Literal["ALLOW", "BLOCK"]
    status: Literal["first_sight", "match", "cosmetic", "drift", "store_error"]
    tool_name: str
    live_hash: str
    approved_hash: str | None
    field_count: int
    latency_ms: float
    changes: list[Change] = field(default_factory=list)
    approved_at: str | None = None
    approved_manifest: dict | None = None
    error: str | None = None

    @property
    def summary(self) -> str:
        return "; ".join(c.describe() for c in self.changes)


# ---------------------------------------------------------------- canonical form

def normalize_manifest(value: Any) -> Any:
    """Collapse whitespace in every string (keys are sorted later by json.dumps)."""
    if isinstance(value, dict):
        return {k: normalize_manifest(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize_manifest(v) for v in value]
    if isinstance(value, str):
        return " ".join(value.split())  # Unicode whitespace only; ZWSP etc. are NOT whitespace
    return value


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_json(manifest: dict) -> str:
    return _dumps(normalize_manifest(manifest))


def fingerprint(manifest: dict) -> str:
    return blake3.blake3(canonical_json(manifest).encode("utf-8")).hexdigest()


def count_fields(value: Any) -> int:
    """Leaf values in the manifest (an empty list counts as one field)."""
    if isinstance(value, dict):
        return sum(count_fields(v) for v in value.values())
    if isinstance(value, list):
        return sum(count_fields(v) for v in value) if value else 1
    return 1


def _ignored(path: str, ignore: frozenset[str]) -> bool:
    return path in ignore or any(path.startswith(f + ".") for f in ignore)


def diff(old: Any, new: Any, ignore_fields: Iterable[str] = (), _path: str = "") -> list[Change]:
    ignore = frozenset(ignore_fields)
    if isinstance(old, dict) and isinstance(new, dict):
        out: list[Change] = []
        for k in sorted(old.keys() | new.keys()):
            p = f"{_path}.{k}" if _path else k
            if _ignored(p, ignore):
                continue
            if k not in new:
                out.append(Change(p, "removed", old[k], None))
            elif k not in old:
                out.append(Change(p, "added", None, new[k]))
            else:
                out.extend(diff(old[k], new[k], ignore, p))
        return out
    return [] if old == new else [Change(_path or "<root>", "changed", old, new)]


# ---------------------------------------------------------------- store

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.executescript(_SCHEMA)
    return conn


def _row(tool_name: str, manifest: dict) -> tuple:
    return (tool_name, _dumps(manifest), canonical_json(manifest), fingerprint(manifest),
            count_fields(manifest), datetime.now(timezone.utc).isoformat(timespec="seconds"))


def approve(tool_name: str, manifest: dict) -> str:
    """Record (or replace) the approved snapshot for a tool. Returns its hash.

    Raises sqlite3.Error if the store is unusable: approval must not silently fail.
    """
    row = _row(tool_name, manifest)
    with closing(_connect()) as conn, conn:
        conn.execute(_UPSERT, row)
    return row[3]


def check(tool_name: str, manifest: dict, ignore_fields: Iterable[str] = ()) -> SchemaCheck:
    t0 = time.perf_counter()
    live_hash = fingerprint(manifest)
    n_fields = count_fields(manifest)

    def done(**kw) -> SchemaCheck:
        return SchemaCheck(tool_name=tool_name, live_hash=live_hash, field_count=n_fields,
                           latency_ms=(time.perf_counter() - t0) * 1000, **kw)

    try:
        with closing(_connect()) as conn:
            row = conn.execute("SELECT raw_json, canonical_json, hash, approved_at "
                               "FROM tool_snapshots WHERE tool_name = ?", (tool_name,)).fetchone()
            if row is None:
                with conn:
                    conn.execute(_UPSERT, _row(tool_name, manifest))
                return done(verdict="ALLOW", status="first_sight", approved_hash=None)
    except sqlite3.Error as e:
        return done(verdict="BLOCK", status="store_error", approved_hash=None,
                    error=f"schema_store_unavailable: {e}")

    approved_raw, approved_canon, approved_hash, approved_at = row
    common = dict(approved_hash=approved_hash, approved_at=approved_at,
                  approved_manifest=json.loads(approved_raw))
    if live_hash == approved_hash:
        status = "match" if _dumps(manifest) == approved_raw else "cosmetic"
        return done(verdict="ALLOW", status=status, **common)
    changes = diff(json.loads(approved_canon), normalize_manifest(manifest), ignore_fields)
    if not changes:  # every difference sits inside ignore_fields
        return done(verdict="ALLOW", status="cosmetic", **common)
    return done(verdict="BLOCK", status="drift", changes=changes, **common)
