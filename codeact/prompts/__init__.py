from pathlib import Path


CONTROLLER_SYSTEM = (Path(__file__).parent / "codeact_agent_prompt.md").read_text(
    encoding="utf-8"
)
