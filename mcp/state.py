from typing import Literal, TypedDict


class AgentState(TypedDict, total=False):
    alert_id: str
    alert: dict
    stage: Literal["classification", "remediation"]
    messages: list
    controller_visits: int
    node_visits: int
    next: Literal["tools", "submit"]
    agent_status: Literal[
        "classified",
        "remediation_completed",
        "error",
        "budget_exhausted",
        "max_steps",
        "no_progress",
    ]
    label: int | None
    rationale: str
    evidence: list[dict]
    observations: list[dict]
    edit_outcome: Literal["edited", "not_edited"]
    remediation_status: Literal["accepted", "rejected", "skipped"]
    remediation_summary: str
