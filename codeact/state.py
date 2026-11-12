from typing import Literal, TypedDict


class AgentState(TypedDict, total=False):
    alert_id: str
    alert: dict
    stage: Literal["classification", "remediation"]
    messages: list
    observations: list[dict]
    node_visits: int
    agent_status: Literal[
                    "classified",
                    "remediation_completed",
                    "error",
                    "budget_exhausted",
                    "max_steps",
                    "no_progress"
                    ]
    next: Literal["tools", "code_action", "submit"]
    label: int | None
    rationale: str
    evidence: list[dict]
    edit_outcome: Literal["edited", "not_edited"]
    remediation_status: Literal["accepted", "rejected", "skipped"]
    remediation_summary: str
