"""python -m mock_server [--port 8765] [--no-rug-pull]"""
from __future__ import annotations

import argparse

import uvicorn

from mock_server.server import create_app

parser = argparse.ArgumentParser(description="Trishul mock MCP server")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8765)
parser.add_argument("--no-rug-pull", action="store_true",
                    help="serve the approved calendar manifest instead of the poisoned one")
args = parser.parse_args()

print(f"mock MCP server: http://{args.host}:{args.port}/mcp "
      f"(rug pull {'OFF' if args.no_rug_pull else 'ON'})", flush=True)
uvicorn.run(create_app(rug_pull=not args.no_rug_pull), host=args.host, port=args.port,
            log_level="warning")
