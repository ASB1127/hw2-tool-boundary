import json
import re

from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from dispatcher import Dispatcher
from langgraph.graph import END, START, StateGraph

from model_runtime import ModelCallDenied, ModelRuntime
from prompts import CONTROLLER_SYSTEM
from state import AgentState
from trace import TerminalStatus, Trace
from kernel import Kernel
from validation import validate_classification, validate_remediation

NO_PROGRESS_LIMIT = 3


def opening_messages(alert: dict, stage: str) -> list:
    if stage not in {"classification", "remediation"}:
        raise ValueError("invalid stage")
    return [
        SystemMessage(content=CONTROLLER_SYSTEM),
        HumanMessage(content=json.dumps({"stage": stage, "alert": alert}, sort_keys=True)),
    ]


def _submission(reply, stage: str, workspace: Path) -> dict:
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
    if stage == "classification":
        return validate_classification(result, workspace)
    if stage == "remediation":
        return validate_remediation(result)
    raise ValueError("invalid stage")

def _script(reply) -> str | None:
    if not isinstance(reply.content, str):
        return None
    match = re.fullmatch(
        r"\s*```python\s*\n(.*?)\n```\s*",
        reply.content,
        flags=re.DOTALL,
    )
    return match.group(1) if match else None

class AgentDAG:
    def __init__(self, trace: Trace | None = None,
                 runtime: ModelRuntime | None = None,
                 kernel: Kernel | None = None,
                 dispatcher: Dispatcher | None = None):
        self.trace = trace
        self.runtime = runtime
        self.kernel = kernel
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
            return {"agent_status": TerminalStatus.MAX_STEPS}
        return {"node_visits": state.get("node_visits", 0) + 1}

    def controller(self,state: AgentState) -> dict:
        if self.runtime is None:
            raise RuntimeError("AgentDAG needs a ModelRuntime")
        visit = self._visit(state)
        if "agent_status" in visit:
            return visit
        try:
            reply = self.runtime.call(state["alert_id"], state.get("messages", []))
        except ModelCallDenied as error:
            if self.trace:
                self.trace.event("routing", alert_id=state["alert_id"],
                                 decision=error.reason, by="runtime")
            return {**visit, "agent_status": error.reason}

        decision = "tools" if getattr(reply, "tool_calls", []) else (
            "code_action" if _script(reply) is not None else "submit"
        )
        if self.trace:
            self.trace.event("state_change", alert_id=state["alert_id"],
                             node="controller", decision=decision)
        return {
            **visit,
            "messages": [*state.get("messages", []), reply],
            "next": decision,
        }

    def tools(self, state: AgentState) -> dict:
        if self.dispatcher is None:
            raise RuntimeError("AgentDAG needs a Dispatcher for tool calls")
        visit = self._visit(state)
        if "agent_status" in visit:
            return visit
        observations = []
        messages = [*state["messages"]]
        for call in state["messages"][-1].tool_calls:
            observation = self.dispatcher({"tool": call["name"], "args": call["args"]})
            observations.append(observation.to_dict())
            messages.append(ToolMessage(
                content=observation.result, tool_call_id=call["id"], name=call["name"],
            ))
        all_observations = [*state.get("observations", []), *observations]
        result = {**visit, "messages": messages, "observations": all_observations}
        if self.stalled(all_observations, NO_PROGRESS_LIMIT):
            result["agent_status"] = TerminalStatus.NO_PROGRESS
        return result

    def code_action(self, state: AgentState) -> dict:
        if self.kernel is None:
            raise RuntimeError("AgentDAG needs a Kernel")
        visit = self._visit(state)
        if "agent_status" in visit:
            return visit
        script = _script(state["messages"][-1])
        if script is None:
            return {**visit, "agent_status": "error"}

        if self.trace:
            self.trace.event(
                "tool_request", alert_id=state["alert_id"], tool="code_action",
                args={}, via="codeact",
            )
        execution = self.kernel.run(script)
        output = execution["output"] if execution["ok"] else execution["error"]
        if self.trace:
            fields = {"ok": execution["ok"], "via": "codeact"}
            fields["chars"] = len(execution["output"])
            fields["stderr_chars"] = len(execution["stderr"])
            if not execution["ok"]:
                fields["error"] = output
            self.trace.event(
                "tool_result", alert_id=state["alert_id"], tool="code_action",
                **fields,
            )
        observation = {"action": "code_action", "result": output, **execution}
        observations = [*state.get("observations", []), observation]
        result = {
            **visit,
            "messages": [*state["messages"], HumanMessage(content=output)],
            "observations": observations,
        }
        if self.stalled(observations, NO_PROGRESS_LIMIT):
            result["agent_status"] = TerminalStatus.NO_PROGRESS
        return result

    def after_controller(self,state: AgentState) -> str:
        if state.get("agent_status"):
            return END
        if self.trace:
            self.trace.event("routing", alert_id=state["alert_id"],
                             decision=state["next"], by="model")
        return state["next"]

    def after_tools(self, state: AgentState) -> str:
        return END if state.get("agent_status") else "controller"

    def after_code_action(self, state: AgentState) -> str:
        return END if state.get("agent_status") else "controller"

    def after_submit(self, state: AgentState) -> str:
        return END if state.get("agent_status") else "controller"

    def submit(self, state: AgentState) -> dict:
        if self.kernel is None:
            raise RuntimeError("AgentDAG needs a Kernel")
        visit = self._visit(state)
        if "agent_status" in visit:
            return visit
        try:
            result = _submission(
                state["messages"][-1], state["stage"], self.kernel.workspace
            )
        except ValueError as error:
            if self.trace:
                self.trace.event("state_change", alert_id=state["alert_id"],
                                 node="submit", error=str(error))
            return {
                **visit,
                "messages": [
                    *state["messages"],
                    HumanMessage(content=f"Invalid final JSON: {error}"),
                ],
            }
        if (state["stage"] == "remediation" and result["edit_outcome"] == "edited"
                and not any(
                    observation.get("action") == "code_action" and observation.get("ok")
                    for observation in state.get("observations", [])
                )):
            return {
                **visit,
                "messages": [
                    *state["messages"],
                    HumanMessage(content=(
                        "You claimed edited, but no successful Python edit script ran. "
                        "Return one fenced Python edit script, then wait for its result."
                    )),
                ],
            }
        if self.trace:
            self.trace.event("state_change", alert_id=state["alert_id"],
                             node="submit", status=result["agent_status"])
        return {**visit, **result}

    def compile(self):
        graph = StateGraph(AgentState)
        graph.add_node("controller", self.controller)
        graph.add_node("tools", self.tools)
        graph.add_node("code_action", self.code_action)
        graph.add_node("submit", self.submit)
        graph.add_edge(START, "controller")
        graph.add_conditional_edges("controller", self.after_controller,
                                    {"tools": "tools", "code_action": "code_action", "submit": "submit", END: END})
        graph.add_conditional_edges("tools", self.after_tools,
                                    {"controller": "controller", END: END})
        graph.add_conditional_edges("code_action", self.after_code_action,
                                    {"controller": "controller", END: END})
        graph.add_conditional_edges("submit", self.after_submit,
                                    {"controller": "controller", END: END})
        return graph.compile()


def build_graph(trace: Trace | None = None,
                runtime: ModelRuntime | None = None,
                kernel: Kernel | None = None,
                dispatcher: Dispatcher | None = None):
    return AgentDAG(trace, runtime, kernel, dispatcher).compile()


def draw_mermaid(trace: Trace | None = None,
                 runtime: ModelRuntime | None = None,
                 kernel: Kernel | None = None,
                 dispatcher: Dispatcher | None = None) -> str:
    return build_graph(trace, runtime, kernel, dispatcher).get_graph().draw_mermaid()


if __name__ == "__main__":
    print(draw_mermaid())
