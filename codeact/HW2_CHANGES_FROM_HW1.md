# CodeAct: changes from HW1

## Files that must change

| File | HW2 change |
|---|---|
| `state.py` | Add the current `stage` (`classification` or `remediation`), CodeAct action/result state, and remediation result fields. |
| `graph.py` | Keep the HW1 control shape, but replace native model tool-call routing with CodeAct routing: a Python script goes to the kernel; its output returns as the next observation. A final JSON response goes to submit. |
| `runner.py` | Create one persistent Python/OpenShell kernel per alert workspace. Start in classification; after a validated label `1`, the runtime invokes remediation; otherwise it records skipped remediation. The runner runs patch checks and writes each report row's `remediation` object. |

## New CodeAct files

| File | Purpose |
|---|---|
| `kernel.py` | Run the model-generated Python scripts inside the sandbox, preserve one namespace for the alert, and return stdout/stderr/traceback as the next observation. |
| `prompts/codeact_agent_prompt.md` | Instruct the model to initialize and reuse CLDK in its generated Python, classify before editing, and return stage-final JSON. |
| `prompts/codeact_prompt_generation_prompt.md` | Required record of the prompt given to Claude Code or Codex to create the agent prompt. |

## Files that stay the same for the CodeAct path

| File | Why |
|---|---|
| `tools.py` | No CodeAct-specific change. CLDK methods are supplied by the SDK and run inside the script; the script can directly read/edit the workspace. |
| `dispatcher.py` | Keep the HW1 dispatcher for the surrounding alert/submit flow. It does not inspect or dispatch the script's internal CLDK/read/edit operations. |
| `workspace.py` | Keep the disposable per-alert workspace and withholding behavior. The new OpenShell sandbox, not `workspace.resolve`, confines generated scripts. |
| `model_runtime.py` | Keep the model-call budget/accounting behavior. |
| `scan.py` | Keep HW1 Bandit discovery. |

## HW2 artifacts/configuration outside `codeact/`

- `report.schema.json` / report construction: each alert gains `remediation` with `accepted`, `rejected`, or `skipped`, the diff, and three check results.
- `trace.schema.json` / graph trace writing: each script run is recorded as `tool_request` then `tool_result` with `via: "codeact"`.
- CodeAct config, OpenShell policy, and README: add the required CLDK/OpenShell setup and launch instructions.

## Remaining CodeAct work

1. **Use `stage` throughout the graph.** The stage exists in `AgentState`, but it must also reach the model's messages and select the correct final-JSON parser in `submit`: classification JSON versus remediation JSON.
2. **Route label-1 alerts to remediation.** After the classification graph returns a validated label `1`, `runner.py` must retain the same workspace and kernel, set `stage = "remediation"`, and invoke the graph again. Label `0`, error, and cutoff rows record remediation `skipped`.
3. **Add remediation acceptance.** After remediation reports completion, the harness computes the workspace diff and runs `applies`, `touches_flagged_line`, and fresh Bandit `clean_rescan`. It derives accepted or rejected; the model never claims these outcomes.
4. **Build the required report object.** `_settle()`/report construction must add `remediation: {status, diff, checks}` to every alert row.
5. **Write CodeAct trace events.** In `graph.py`'s code-action node, write one adjacent `tool_request`/`tool_result` pair around every `kernel.run(script)`, both with `via: "codeact"`. The kernel should return structured success/output information so the graph can record the result. After acceptance, write one `state_change` with `node: "remediation"` and the three checks; it must omit `alert_status` and `label`.
6. **Run inside OpenShell and test.** `kernel.py` may use in-process `exec` because the whole CodeAct agent is launched under OpenShell. Do not launch OpenShell per script. Test namespace persistence, traceback handling, CodeAct trace-event adjacency, stage routing, all remediation outcomes, and report-schema validation.

## Key ownership

```text
runner: chooses the stage; routes validated label 1 to remediation
controller/model: chooses the next Python script or current-stage final JSON
kernel: runs the script
CLDK: implements analysis.locate(), get_ddg(), callers_of(), etc.
```
