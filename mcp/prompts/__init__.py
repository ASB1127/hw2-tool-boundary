from pathlib import Path


CONTROLLER_SYSTEM = (Path(__file__).parent / "mcp_agent_prompt.md").read_text(
    encoding="utf-8"
)
