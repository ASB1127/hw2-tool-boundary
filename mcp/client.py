from __future__ import annotations

import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client import stdio as mcp_stdio
from mcp.client.stdio import stdio_client


MCP_SHUTDOWN_GRACE_SECONDS = 15.0
# shortcut: waits at most 15 seconds; increase only if clean shutdowns exceed it.
mcp_stdio.PROCESS_TERMINATION_TIMEOUT = MCP_SHUTDOWN_GRACE_SECONDS


class MCPClient:
    def __init__(self, workspace: str, config_path: Path):
        server = json.loads(Path(config_path).read_text(encoding="utf-8"))["mcpServers"]["analysis"]
        args = list(server["args"])
        args[args.index("--workspace") + 1] = workspace
        self.params = StdioServerParameters(
            command=server["command"],
            args=args,
            env=server.get("env"),
        )
        self.transport = None
        self.session = None

    async def connect(self):
        self.transport = stdio_client(self.params)
        read_stream, write_stream = await self.transport.__aenter__()
        self.session = ClientSession(read_stream, write_stream)
        await self.session.__aenter__()
        await self.session.initialize()
        return (await self.session.list_tools()).tools

    async def call_tool(self, name: str, arguments: dict):
        if self.session is None:
            raise RuntimeError("MCP client is not connected")
        return await self.session.call_tool(name, arguments)

    async def close(self) -> None:
        if self.session is not None:
            await self.session.__aexit__(None, None, None)
            self.session = None
        if self.transport is not None:
            await self.transport.__aexit__(None, None, None)
            self.transport = None
