"""Export Sentinel MCP server tool definitions as static JSON for scanning.

Generates the tools JSON that mcp-scanner expects in static mode,
without needing to start the actual MCP server (which requires env vars).

Usage: python -m evals.export_mcp_tools > evals/mcp-tools.json
"""

from __future__ import annotations

import asyncio
import json


async def _export() -> list[dict]:
    from pipeline.mcp_server import mcp

    tools = await mcp.list_tools()
    result = []
    for t in tools:
        tool_def = {
            "name": t.name,
            "description": t.description or "",
            "inputSchema": t.parameters if hasattr(t, "parameters") else {},
        }
        result.append(tool_def)
    return result


if __name__ == "__main__":
    definitions = asyncio.run(_export())
    print(json.dumps({"tools": definitions}, indent=2))
