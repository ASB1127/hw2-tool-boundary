from __future__ import annotations

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPClient:
    def __init__(self, workspace: str):
        self.params = StdioServerParameters(
            command="/usr/local/bin/python3.12",
            args=["-m", "server", "--workspace", workspace],
            env={
                "SYSTEM_PYTHON": "/usr/local/bin/python3.12",
                "PYTHONPATH": "/app/mcp:/app",
            },
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
