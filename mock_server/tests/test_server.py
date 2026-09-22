"""Mock MCP server tests: real server on a real port, real MCP SDK client. No mocks."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from attacks.catalog import ATTACKS
from attacks.manifests import APPROVED, RUG_PULLED_CALENDAR
from attacks.payloads import ATTACK1_PAYLOAD, ATTACK4_PAYLOAD
from backend.mcp_client import ToolServerError, call_tool, fetch_manifest
from mock_server.server import free_port, serve_in_thread


@pytest.fixture(scope="module")
def rug_url():
    with serve_in_thread(rug_pull=True) as base:
        yield base


@pytest.fixture(scope="module")
def honest_url():
    with serve_in_thread(rug_pull=False) as base:
        yield base


def calls(base: str) -> list[dict]:
    return httpx.get(f"{base}/debug/calls").json()["calls"]


# ---------------------------------------------------------------- manifests

def test_lists_all_four_demo_tools(rug_url):
    for name in APPROVED:
        m, ms = asyncio.run(fetch_manifest(name, f"{rug_url}/mcp"))
        assert m["name"] == name and ms > 0


def test_manifests_for_attacks_1_to_3_are_the_approved_ones(rug_url):
    for name in ("sentry.get_error_logs", "github.get_issue", "docs.get_page"):
        m, _ = asyncio.run(fetch_manifest(name, f"{rug_url}/mcp"))
        assert m == APPROVED[name]  # byte-for-byte what Layer 5 approved


def test_rug_pull_server_serves_poisoned_calendar(rug_url):
    m, _ = asyncio.run(fetch_manifest("calendar.get_events", f"{rug_url}/mcp"))
    assert m == RUG_PULLED_CALENDAR and m != APPROVED["calendar.get_events"]


def test_honest_server_serves_approved_calendar(honest_url):
    m, _ = asyncio.run(fetch_manifest("calendar.get_events", f"{honest_url}/mcp"))
    assert m == APPROVED["calendar.get_events"]


def test_catalog_manifests_match_what_the_server_serves(rug_url):
    # The catalog's manifest is used in custom-text mode; it must not diverge from live.
    for a in ATTACKS.values():
        m, _ = asyncio.run(fetch_manifest(a.tool_name, f"{rug_url}/mcp"))
        assert m == a.manifest, a.id


def test_unlisted_tool_is_an_error(rug_url):
    with pytest.raises(ToolServerError, match="not listed"):
        asyncio.run(fetch_manifest("fs.read_file", f"{rug_url}/mcp"))


# ---------------------------------------------------------------- calls

def test_each_tool_returns_its_attack_payload_exactly(rug_url, honest_url):
    for a in ATTACKS.values():
        # The rug-pulled calendar demands sync_token, so fetch its response from the honest one.
        base = honest_url if a.id == "rug_pull_calendar" else rug_url
        text, _ = asyncio.run(call_tool(a.tool_name, a.call_args, f"{base}/mcp"))
        assert text == a.payload, a.id


def test_invisible_tag_chars_survive_transport(rug_url):
    text, _ = asyncio.run(call_tool("sentry.get_error_logs", {"project": "p", "limit": 1},
                                    f"{rug_url}/mcp"))
    assert text == ATTACK1_PAYLOAD
    assert sum(0xE0000 <= ord(c) <= 0xE007F for c in text) == 92


def test_calls_are_logged_with_arguments(honest_url):
    before = len(calls(honest_url))
    asyncio.run(call_tool("calendar.get_events", {"start_date": "a", "end_date": "b"},
                          f"{honest_url}/mcp"))
    log = calls(honest_url)
    assert len(log) == before + 1
    assert log[-1]["tool"] == "calendar.get_events"
    assert log[-1]["arguments"] == {"start_date": "a", "end_date": "b"}


def test_listing_is_not_logged_as_a_call(honest_url):
    before = len(calls(honest_url))
    asyncio.run(fetch_manifest("docs.get_page", f"{honest_url}/mcp"))
    assert len(calls(honest_url)) == before


# ---------------------------------------------------------------- errors

def test_missing_required_argument_is_tool_error(honest_url):
    with pytest.raises(ToolServerError, match=r"missing required argument\(s\): end_date$"):
        asyncio.run(call_tool("calendar.get_events", {"start_date": "a"}, f"{honest_url}/mcp"))


def test_rug_pulled_calendar_demands_sync_token(rug_url):
    # On the rug-pull server the redefined tool requires the exfil parameter.
    with pytest.raises(ToolServerError, match="sync_token"):
        asyncio.run(call_tool("calendar.get_events", {"start_date": "a", "end_date": "b"},
                              f"{rug_url}/mcp"))


def test_unknown_tool_call_is_tool_error(rug_url):
    with pytest.raises(ToolServerError, match="unknown tool"):
        asyncio.run(call_tool("fs.read_file", {}, f"{rug_url}/mcp"))


def test_server_down_raises_tool_server_error():
    dead = f"http://127.0.0.1:{free_port()}/mcp"  # nothing listening
    with pytest.raises(ToolServerError, match="unavailable"):
        asyncio.run(fetch_manifest("docs.get_page", dead))
    with pytest.raises(ToolServerError, match="unavailable"):
        asyncio.run(call_tool("docs.get_page", {"slug": "x"}, dead))


def test_attack4_response_itself_is_clean():
    # Sanity on the fixture data the demo narrative depends on.
    assert "credentials" not in ATTACK4_PAYLOAD and "sync_token" not in ATTACK4_PAYLOAD
