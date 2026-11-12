import json
import re

from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from dispatcher import Dispatcher
from model_runtime import ModelCallDenied, ModelRuntime
from prompts import CONTROLLER_SYSTEM
from state import AgentState
from trace import TerminalStatus, Trace
from workspace import PathEscapeException, resolve


NO_PROGRESS_LIMIT = 3


def opening_messages(alert: dict) -> list:
    return [
        SystemMessage(content=CONTROLLER_SYSTEM),
        HumanMessage(content=json.dumps(alert, sort_keys=True)),
    ]


def validate_classification(result, workspace: Path) -> dict:
    if not isinstance(result, dict):
        raise ValueError("classification is not an object")
    label = result.get("label")
    rationale = result.get("rationale")
    evidence = result.get("evidence")
    if type(label) is not int or label not in (0, 1):
        raise ValueError("label must be 0 or 1")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("rationale must be non-empty text")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("evidence must be a non-empty list")

    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError("evidence item must be an object")
        path = item.get("path")
        start = item.get("start_line")
        end = item.get("end_line")
        if (not isinstance(path, str) or not path or path.startswith("./")
                or "\\" in path or type(start) is not int or type(end) is not int
                or start < 1 or end < start):
            raise ValueError("invalid evidence range")
        try:
            target = resolve(workspace, path)
        except PathEscapeException as error:
            raise ValueError("evidence path is outside the workspace") from error
        if not target.is_file():
            raise ValueError(f"evidence file does not exist: {path}")
        if end > len(target.read_text(encoding="utf-8", errors="replace").splitlines()):
            raise ValueError(f"evidence range is outside {path}")

    return {"status": "classified", "label": label,
            "rationale": rationale, "evidence": evidence}


def _submission(reply, workspace: Path) -> dict:
    if not isinstance(reply.content, str):
        raise ValueError("model reply is not text")
    try:
        result = json.loads(reply.content)
    except json.JSONDecodeError:
        fenced = re.findall(
            r"```(?:json)?\s*(\{.*?\})\s*```", reply.content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if len(fenced) != 1:
            raise ValueError("model reply is not one JSON object")
        try:
            result = json.loads(fenced[0])
        except json.JSONDecodeError as error:
            raise ValueError("model reply is not one JSON object") from error
    return validate_classification(result, workspace)

class AgentDAG:
    def __init__(self, trace: Trace | None = None,
                 runtime: ModelRuntime | None = None,
                 dispatcher: Dispatcher | None = None):
        self.trace = trace
        self.runtime = runtime
        self.dispatcher = dispatcher

    @staticmethod
    def stalled(observations:list, limit:int) -> bool:
        if len(observations) < limit:
            return False
        recent = [o.get("result") for o in observations[-limit:]]
        return all(result == recent[0] for result in recent)

    def _visit(self, state: AgentState) -> dict:
        if state.get("node_visits", 0) >= self.runtime.config.budget["max_steps"]:
            if self.trace:
                self.trace.event("routing", alert_id=state["alert_id"],
                                 decision=TerminalStatus.MAX_STEPS, by="runtime")
            return {"status": TerminalStatus.MAX_STEPS}
        return {"node_visits": state.get("node_visits", 0) + 1}

    def controller(self,state: AgentState) -> dict:
        if self.runtime is None:
            raise RuntimeError("AgentDAG needs a ModelRuntime")
        visit = self._visit(state)
        if "status" in visit:
            return visit
        try:
            reply = self.runtime.call(state["alert_id"], state.get("messages", []))
        except ModelCallDenied as error:
            if self.trace:
                self.trace.event("routing", alert_id=state["alert_id"],
                                 decision=error.reason, by="runtime")
            return {**visit, "status": error.reason}

        decision = "tools" if getattr(reply, "tool_calls", []) else "submit"
        if self.trace:
            self.trace.event("state_change", alert_id=state["alert_id"],
                             node="controller", decision=decision)
        return {
            **visit,
            "controller_visits": state.get("controller_visits", 0) + 1,
            "messages": [*state.get("messages", []), reply],
            "next": decision,
        }

    def tools(self,state: AgentState) -> dict:
        if self.dispatcher is None:
            raise RuntimeError("AgentDAG needs an alert Dispatcher")
        visit = self._visit(state)
        if "status" in visit:
            return visit
        calls = state["messages"][-1].tool_calls
        observations = []
        messages = [*state["messages"]]
        for call in calls:
            observation = self.dispatcher({"tool": call["name"], "args": call["args"]})
            observations.append(observation.to_dict())
            messages.append(ToolMessage(
                content=observation.result,
                tool_call_id=call["id"],
                name=call["name"],
            ))
        all_observations = [*state.get("observations", []), *observations]
        if self.trace:
            self.trace.event("state_change", alert_id=state["alert_id"],
                             node="tools", observations=observations)
        result = {**visit, "messages": messages, "observations": all_observations}
        if self.stalled(all_observations, NO_PROGRESS_LIMIT):
            if self.trace:
                self.trace.event("routing", alert_id=state["alert_id"],
                                 decision=TerminalStatus.NO_PROGRESS, by="runtime")
            result["status"] = TerminalStatus.NO_PROGRESS
        return result

    def after_controller(self,state: AgentState) -> str:
        if state.get("status"):
            return END
        if self.trace:
            self.trace.event("routing", alert_id=state["alert_id"],
                             decision=state["next"], by="model")
        return state["next"]

    def after_tools(self, state: AgentState) -> str:
        return END if state.get("status") else "controller"

    def after_submit(self,state: AgentState) -> str:
        return END

    def submit(self, state: AgentState) -> dict:
        if self.dispatcher is None:
            raise RuntimeError("AgentDAG needs an alert Dispatcher")
        visit = self._visit(state)
        if "status" in visit:
            return visit
        try:
            result = _submission(state["messages"][-1], self.dispatcher.ws)
        except ValueError as error:
            result = {"status": "error", "label": None,
                      "rationale": str(error), "evidence": []}
        if self.trace:
            self.trace.event("state_change", alert_id=state["alert_id"],
                             node="submit", status=result["status"])
        return {**visit, **result}

    def compile(self):
        graph = StateGraph(AgentState)
        graph.add_node("controller", self.controller)
        graph.add_node("tools", self.tools)
        graph.add_node("submit", self.submit)
        graph.add_edge(START, "controller")
        graph.add_conditional_edges("controller", self.after_controller,
                                    {"tools": "tools", "submit": "submit", END: END})
        graph.add_conditional_edges("tools", self.after_tools,
                                    {"controller": "controller", END: END})
        graph.add_conditional_edges("submit", self.after_submit, {END: END})
        return graph.compile()


def build_graph(trace: Trace | None = None,
                runtime: ModelRuntime | None = None,
                dispatcher: Dispatcher | None = None):
    return AgentDAG(trace, runtime, dispatcher).compile()


def draw_mermaid(trace: Trace | None = None,
                 runtime: ModelRuntime | None = None,
                 dispatcher: Dispatcher | None = None) -> str:
    return build_graph(trace, runtime, dispatcher).get_graph().draw_mermaid()


if __name__ == "__main__":
    print(draw_mermaid())
