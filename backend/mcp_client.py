"""MCP client side of the backend: fetch a tool's live manifest, and call it.

Two separate short sessions on purpose: the manifest is fetched, Layer 5 judges
it, and only then is a second session opened to forward the call. A call that
Layer 5 blocks is therefore never sent to the server.

The SDK's client-side response cache is disabled (cache=None): a cached
tools/list would hide a rug pull from Layer 5.

Any transport/protocol failure raises ToolServerError. The backend reports it
as HTTP 502; it is not a security verdict, since nothing was inspected.
"""
from __future__ import annotations

import os
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import anyio
import httpx
import httpx2  # the mcp SDK's HTTP transport is built on httpx2, not httpx
from mcp import Client, MCPError

DEFAULT_URL = "http://127.0.0.1:8765/mcp"
TIMEOUT_S = 10.0
_TRANSPORT_ERRORS = (httpx2.HTTPError, httpx.HTTPError, MCPError, TimeoutError)

T = TypeVar("T")


def server_url() -> str:
    return os.environ.get("TRISHUL_MCP_URL", DEFAULT_URL)


class ToolServerError(RuntimeError):
    """The MCP server could not be reached, or the tool call itself failed."""


async def _session(fn: Callable[[Client], Awaitable[T]], url: str) -> T:
    try:
        with anyio.fail_after(TIMEOUT_S):
            async with Client(url, cache=None, read_timeout_seconds=TIMEOUT_S) as client:
                return await fn(client)
    except _TRANSPORT_ERRORS as e:
        raise ToolServerError(f"MCP server {url} unavailable: {e!r}") from e
    except BaseExceptionGroup as eg:  # the SDK's task group wraps transport errors
        _, rest = eg.split(_TRANSPORT_ERRORS)
        if rest is not None:
            raise
        raise ToolServerError(f"MCP server {url} unavailable: {eg.exceptions[0]!r}") from eg


async def fetch_manifest(tool_name: str, url: str | None = None) -> tuple[dict, float]:
    """tools/list, then pick one tool. Returns (manifest, latency_ms)."""
    url = url or server_url()
    t0 = time.perf_counter()

    async def list_tools(client: Client):
        return (await client.list_tools()).tools

    tools = await _session(list_tools, url)
    for t in tools:
        if t.name == tool_name:
            manifest = {"name": t.name, "description": t.description or "",
                        "inputSchema": t.input_schema}
            return manifest, (time.perf_counter() - t0) * 1000
    raise ToolServerError(f"tool {tool_name!r} is not listed by MCP server {url}")


async def call_tool(tool_name: str, arguments: dict[str, Any],
                    url: str | None = None) -> tuple[str, float]:
    """tools/call. Returns (concatenated text content, latency_ms)."""
    url = url or server_url()
    t0 = time.perf_counter()

    async def call(client: Client):
        return await client.call_tool(tool_name, arguments)

    result = await _session(call, url)
    texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    if result.is_error:
        raise ToolServerError(f"tool {tool_name!r} returned an error: {' '.join(texts)}")
    if len(texts) != len(result.content):
        raise ToolServerError(f"tool {tool_name!r} returned non-text content (unsupported in demo)")
    return "".join(texts), (time.perf_counter() - t0) * 1000
