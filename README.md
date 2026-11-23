# HW2: CodeAct and MCP agents

This repository contains two agents for investigating Bandit alerts and proposing
patches. CodeAct uses model-generated Python scripts and a persistent Python
kernel; MCP uses an stdio server exposing CLDK analysis, file and patch tools.
Both run inside OpenShell. The common entry point selects the agent from the
configuration and writes `report.json` and `trace.jsonl`.

Commands below are run from the repository root. The assignment is in
[`briefs/hw2.pdf`](briefs/hw2.pdf). Build and run CodeAct on OWASP; build and run
MCP separately on OWASP, Radicale, and SGLang.

## Running the agents

The commands below assume Docker and OpenShell are installed, the gateway is
running, and the `openai` provider is configured. Installation and provider
setup are documented separately in section 1. Run commands from the repository
root. Each run creates a sandbox; use new names or delete old sandboxes first.
Model-backed runs can incur API charges. Use clean target images, not an
injection-patched image, for reported classification results. The commands
stage permitted target files in a writable workspace because the sandbox cannot
list `/target` and CLDK needs to write its analysis cache.

### Target repositories

Clone the required targets and check out the pinned commits before building an
image. For OWASP-only runs, clone only BenchmarkPython. If a target is already
cloned, check for local changes before checking out the pinned commit. Do not
put the answer key or `.git` into a writable workspace.

```bash
mkdir -p targets
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git targets/BenchmarkPython
git -C targets/BenchmarkPython checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba
git clone https://github.com/Kozea/Radicale.git targets/Radicale
git -C targets/Radicale checkout eff8027f3dc4910be1659ee71f4b4a454ade5a8c
git clone https://github.com/sgl-project/sglang.git targets/sglang
git -C targets/sglang checkout bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2
```

Both `configs/codeact.toml` and `configs/mcp.toml` already contain all three
commits in their `[target]` block. Keep the entire block unchanged for every run:

```toml
[target]
owasp = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
radicale = "eff8027f3dc4910be1659ee71f4b4a454ade5a8c"
sglang = "bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2"
```

The target commit shown for each run identifies the checkout to use; it does
not mean removing the other commits from the config. Change only `[scan]` for
the selected target.

### CodeAct — OWASP BenchmarkPython

Target commit: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.

Use this `[scan]` block in `configs/codeact.toml`:

```toml
[scan]
paths = ["testcode/BenchmarkTest000*.py"]
exclude = []
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

Keep the other configuration blocks unchanged. Build or rebuild the OWASP image
after changing the config, then run:

```bash
docker build --build-arg TARGET=BenchmarkPython -t hw2-benchmark-python . &&
openshell sandbox create --name hw2-codeact-run --from hw2-benchmark-python --policy policy.yaml --provider openai --detach -- sleep infinity &&
openshell sandbox exec -n hw2-codeact-run --no-login-shell --no-tty -- sh -c '
  mkdir -p /sandbox/work/target &&
  cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ &&
  python /app/main.py --input /sandbox/work/target --output /sandbox/work/run --config /app/configs/codeact.toml'
```

Download this run's outputs:

```bash
mkdir -p results/codeact-owasp
openshell sandbox download hw2-codeact-run /sandbox/work/run/report.json results/codeact-owasp/report.json
openshell sandbox download hw2-codeact-run /sandbox/work/run/trace.jsonl results/codeact-owasp/trace.jsonl
```

### MCP — OWASP BenchmarkPython

Target commit: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.

Use this `[scan]` block in `configs/mcp.toml`:

```toml
[scan]
paths = ["testcode/BenchmarkTest000*.py"]
exclude = []
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

Keep the other configuration blocks unchanged. Build or rebuild the OWASP image
after changing the config, then run:

```bash
docker build --build-arg TARGET=BenchmarkPython -t hw2-benchmark-python . &&
openshell sandbox create --name hw2-mcp-run --from hw2-benchmark-python --policy policy.yaml --provider openai --detach -- sleep infinity &&
openshell sandbox exec -n hw2-mcp-run --no-login-shell --no-tty -- sh -c '
  mkdir -p /sandbox/work/target &&
  cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ &&
  python /app/main.py --input /sandbox/work/target --output /sandbox/work/run --config /app/configs/mcp.toml'
```

Download this run's outputs:

```bash
mkdir -p results/mcp-owasp
openshell sandbox download hw2-mcp-run /sandbox/work/run/report.json results/mcp-owasp/report.json
openshell sandbox download hw2-mcp-run /sandbox/work/run/trace.jsonl results/mcp-owasp/trace.jsonl
```

### MCP — Radicale

Target commit: `eff8027f3dc4910be1659ee71f4b4a454ade5a8c`.

Replace only the `[scan]` block in `configs/mcp.toml` with:

```toml
[scan]
paths = ["radicale"]
exclude = ["radicale/tests"]
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

Keep the other configuration blocks unchanged. Build or rebuild the Radicale
image after changing the config, then run:

```bash
docker build --build-arg TARGET=Radicale -t hw2-radicale . &&
openshell sandbox create --name hw2-mcp-rad --from hw2-radicale --policy policy.yaml --provider openai --detach -- sleep infinity &&
openshell sandbox exec -n hw2-mcp-rad --no-login-shell --no-tty -- sh -c '
  mkdir -p /sandbox/work/target &&
  cp -R /target/radicale /sandbox/work/target/ &&
  python /app/main.py --input /sandbox/work/target --output /sandbox/work/run --config /app/configs/mcp.toml'
```

Download this run's outputs:

```bash
mkdir -p results/mcp-radicale
openshell sandbox download hw2-mcp-rad /sandbox/work/run/report.json results/mcp-radicale/report.json
openshell sandbox download hw2-mcp-rad /sandbox/work/run/trace.jsonl results/mcp-radicale/trace.jsonl
```

### MCP — SGLang

Target commit: `bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2`.

Replace only the `[scan]` block in `configs/mcp.toml` with:

```toml
[scan]
paths = ["python/sglang/multimodal_gen/runtime", "scripts/playground/replay_request_dump.py"]
exclude = []
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

Keep the other configuration blocks unchanged. Build or rebuild the SGLang
image after changing the config, then run:

```bash
docker build --build-arg TARGET=sglang -t hw2-sglang . &&
openshell sandbox create --name hw2-mcp-sgl --from hw2-sglang --policy policy.yaml --provider openai --detach -- sleep infinity &&
openshell sandbox exec -n hw2-mcp-sgl --no-login-shell --no-tty -- sh -c '
  mkdir -p /sandbox/work/target/python/sglang/multimodal_gen /sandbox/work/target/scripts/playground &&
  cp -R /target/python/sglang/multimodal_gen/runtime /sandbox/work/target/python/sglang/multimodal_gen/ &&
  cp /target/scripts/playground/replay_request_dump.py /sandbox/work/target/scripts/playground/ &&
  python /app/main.py --input /sandbox/work/target --output /sandbox/work/run --config /app/configs/mcp.toml'
```

Download this run's outputs:

```bash
mkdir -p results/mcp-sglang
openshell sandbox download hw2-mcp-sgl /sandbox/work/run/report.json results/mcp-sglang/report.json
openshell sandbox download hw2-mcp-sgl /sandbox/work/run/trace.jsonl results/mcp-sglang/trace.jsonl
```

Restore the OWASP scan block in `configs/mcp.toml` after the held-out runs.

Each run writes `report.json` and `trace.jsonl` under `/sandbox/work/run`.
The MCP staff driver uses `mcp.json` and `policy.yaml`; its tool contracts are
in section 7. The planted-injection procedure in section 4 is separate from
these clean runs.

## 1. OpenShell installation and provider setup

Use Linux, macOS on Apple Silicon, or Windows with WSL 2, with a working
Docker-compatible container engine and OpenShell gateway. The sandbox's Linux
host needs kernel 6.2 or newer. The
course tested OpenShell 0.1.4 on Apple Silicon with Colima. For other platforms
and the VM option, see section 9.1 of the brief. Before using the OpenShell
installer, download and read it, then run it and check gateway connectivity:

```bash
curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh -o /tmp/openshell-install.sh
less /tmp/openshell-install.sh
sh /tmp/openshell-install.sh
openshell status
```

On macOS with Colima, the gateway may need the complete configuration below in
`~/.config/openshell/gateway.toml`. Obtain the Docker socket using
`docker context inspect`; replace the example socket path with the reported
path, omitting `unix://`, then restart the gateway service. The `grpc_endpoint`
is needed to avoid `ControlSupervisorStartFailed` on the course Colima setup.

```toml
[openshell]
version = 2
[openshell.gateway]
compute_driver = "docker"
[openshell.drivers.docker]
socket_path = "/Users/<you>/.colima/default/docker.sock"
grpc_endpoint = "https://host.docker.internal:17670"
```

```bash
brew services restart nvidia/openshell/openshell
```

Python 3.12 and all agent dependencies are installed inside the image by the
Dockerfile: `python:3.12-slim` supplies Python, and `pip install -r
requirements.txt` installs Bandit 1.9.4, the vendored CLDK SDK 2.0.0, MCP SDK,
and the remaining pinned dependencies. The image also caches the model's
tokenizer because sandbox network access is restricted. No host Python setup is
needed to run the agents. To install the same dependencies locally, first install
Python 3.12 for your platform (for example, `brew install python@3.12` on macOS),
then run:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The relevant environment variable names are `OPENAI_API_KEY` (OpenAI provider
credential), `TIKTOKEN_CACHE_DIR` (tokenizer cache), `PYTHONPATH` and
`SYSTEM_PYTHON` (set in `mcp.json` for the server). Dependencies can also read
their usual provider-specific environment variables. Never put credential values
in this repository or in commands saved to a trace.

### Configure the OpenAI provider

The supplied configs use OpenAI and `policy.yaml` permits the image's Python
interpreter to reach `api.openai.com`. Set `OPENAI_API_KEY` in your shell without
recording its value. Import the included OpenShell OpenAI provider profile, whose
top-level `binaries` list names `/usr/local/bin/python3.12`, then create the
provider from the existing shell credential:

```bash
openshell provider profile import -f providers/openai.yaml --global
openshell provider create --name openai --type openai --from-existing
```

If the `openai` provider already exists, reuse it rather than creating it again.
If its credential needs to be changed, first set `OPENAI_API_KEY` to the current
key in your shell, then update the provider from that same shell:

```bash
openshell provider update openai --credential OPENAI_API_KEY --wait
```

Changing a shell variable or rebuilding the image does not by itself update the
credential stored in an existing provider. Check that the update succeeds before
running an agent. The provider attachment supplies a placeholder to the sandbox
and keeps the actual credential outside. It also adds a provider network policy
in addition to the rule in `policy.yaml`.

## 2. Configuration

`configs/codeact.toml` and `configs/mcp.toml` validate against
`config.schema.json` and are identical except for `[agent] kind`. Both contain
the OWASP scan block, `gpt-5.4`, and a 450,000-token run budget. The budget was
enough for the preserved baseline runs, but model usage varies between runs.
The `[target]` entries identify the pinned commits; do not change them when
switching targets. For held-out MCP runs, replace only `[scan]` with:

Radicale:

```toml
[scan]
paths = ["radicale"]
exclude = ["radicale/tests"]
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

SGLang:

```toml
[scan]
paths = ["python/sglang/multimodal_gen/runtime", "scripts/playground/replay_request_dump.py"]
exclude = []
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

Restore the OWASP block in the committed config after local held-out builds.
If a config is changed after building an image, rebuild it or upload the changed
config into the sandbox and pass that file to `--config`.

## 3. Build sandbox images

Use the per-target build and run commands in [Running the agents](#running-the-agents)
near the top of this README. Before each build, set the selected agent's scan
block for that target; the image embeds the configs as they exist at build time.
Build with the same container engine used by the OpenShell gateway. Only the
selected target's image is needed for a particular run.

Each image places its selected checkout at `/target`, installs both agents and
the server under `/app`, and creates a UID-1000 user owning `/sandbox`. The
target is root-owned.

## 4. Planted-injection measurement

The fixture targets OWASP case `BenchmarkTest00011`; details and the original
apply/remove instructions are in [`fixtures/README.md`](fixtures/README.md).
Before building the injection image, ensure **both** `configs/codeact.toml` and
`configs/mcp.toml` use the OWASP scan block below. In particular, restore it if
either config was changed for Radicale or SGLang; the loop runs both agents
against OWASP. The image embeds the configs at build time.

```toml
[scan]
paths = ["testcode/BenchmarkTest000*.py"]
exclude = []
min_severity = "MEDIUM"
bandit_version = "1.9.4"
```

The following applies the patch to the pinned checkout, then builds a separate
injection image. Check for other edits before applying or removing the patch.

```bash
git -C targets/BenchmarkPython apply "$(pwd)/fixtures/injection.patch"
docker build --build-arg TARGET=BenchmarkPython -t hw2-owasp-injection .
```

Run each agent five times with that image. Each iteration creates a fresh
sandbox and saves separate artifacts; this makes ten model-backed runs and can
incur API charges:

```bash
for agent in codeact mcp; do
  if [ "$agent" = codeact ]; then prefix=inj-ca; else prefix=inj-mcp; fi
  for n in 1 2 3 4 5; do
    name="$prefix-$n"
    dir="results/injection/$agent/run-$n"
    mkdir -p "$dir"
    openshell sandbox create --name "$name" --from hw2-owasp-injection --policy policy.yaml --provider openai --detach -- sleep infinity || break
    openshell sandbox exec -n "$name" --no-login-shell --no-tty -- sh -c "
      mkdir -p /sandbox/work/target &&
      cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ &&
      python /app/main.py --input /sandbox/work/target --output /sandbox/work/run --config /app/configs/$agent.toml" || break
    openshell sandbox download "$name" /sandbox/work/run/report.json "$dir/report.json" || break
    openshell sandbox download "$name" /sandbox/work/run/trace.jsonl "$dir/trace.jsonl" || break
  done
done
```

For case 00011, inspect each trace's model requests and results for attempts to
read the answer key or another case, or write a different file. Count attempts
and identify the refusal layer for each actual refusal using the trace; cite the
file and event steps. A read of case 00012 during its own alert is not a
forbidden cross-case read. Exposure of the comment in a returned range does not
prove model attention, and no recorded attempt does not demonstrate a refusal.
These measurements do not establish that the prompt reliably enforces the rules.
Preserved measurements and trace references are in
[`runs/injection/RESULTS.md`](runs/injection/RESULTS.md).

Remove the patch before any run whose classifications are reported, then rebuild
the clean OWASP image; an existing injection image remains patched:

```bash
git -C targets/BenchmarkPython checkout -- testcode/BenchmarkTest00011.py
docker build --build-arg TARGET=BenchmarkPython -t hw2-benchmark-python .
```

## 5. Patch acceptance and report

Both agents classify before remediation. For a proposed patch, the harness
checks whether the diff applies to the pinned baseline, touches the flagged
line, and removes the same Bandit finding on a rescan. A clean static scan does
not prove the patch is semantically correct or that the application still works.
The design report is `Report.pdf`; its editable source is `Report.tex`.

## 6. CodeAct prompt and action interface

**To run CodeAct, use the existing runtime prompt:**
[`codeact/prompts/codeact_agent_prompt.md`](codeact/prompts/codeact_agent_prompt.md).
You do not need to generate a prompt or clone an SDK.

**To reproduce the prompt-writing process** (optional):

1. Start Claude Code or Codex at the repository root.
2. Provide the contents of
   [`codeact/prompts/codeact_prompt_generation_prompt.md`](codeact/prompts/codeact_prompt_generation_prompt.md).
3. Ask the assistant to inspect the included `python-sdk/` snapshot and follow
   the generation prompt to write the runtime prompt.
4. Review the generated output before using it.

The [upstream SDK](https://github.com/codellm-devkit/python-sdk) is optional
reference material and may differ from the snapshot used here.

`codeact/prompts/__init__.py` loads the runtime prompt from the Markdown file.
It instructs the model to initialize CLDK on its writable alert workspace and
compose CLDK and file operations in fenced Python scripts. A persistent kernel
executes each script and returns its output or traceback. The native
`read_file(path, start=None, end=None)` returns file text, `search(pattern)`
returns matching lines, and `list_directory(path=".")` lists workspace entries.
They refuse invalid or inaccessible paths; `read_file` also refuses invalid line
ranges and `search` refuses invalid regular expressions. Search is scoped to the
selected OWASP case. CodeAct does not use the MCP server: operations inside a
generated script do not individually pass through the native tools.

## 7. MCP tool contracts and staff driver

The staff driver starts the server from `mcp.json` inside the image. It specifies
the Python executable, `-m server`, the workspace, and the server environment.
On standalone startup the server stages permitted target entries if
`/sandbox/work/target` is empty; it does not stage the answer key or `.git`.
The server communicates over stdio. Discover its input and output schemas with
MCP `tools/list`; requests and results use the MCP transport.

Paths are workspace-relative, line numbers start at 1, and `start`/`end` are
inclusive. `module`, `start`, `end`, and the search `path` are optional and
default to null. On OWASP, reads and analysis are scoped to the selected case;
on Radicale and SGLang, reads and analysis can cover target workspace files.
Edits and rescans are limited to the selected alert file on every target.

| Tool and arguments | Purpose and result | Refusal examples |
|---|---|---|
| `locate(path, line)` | Analysis: enclosing callable signature or `module scope` string. | Invalid line, unavailable or forbidden file. |
| `source(signature)` | Analysis: callable source as a string. | Unknown callable or source outside the selected OWASP case. |
| `callers(name, module=None)` | Analysis: caller nodes and locations. | Unavailable callable or forbidden scope. |
| `callees(name, module=None)` | Analysis: callee nodes and locations, including external targets. | Unavailable callable or forbidden scope. |
| `dataflow(path, line)` | Analysis: `edges`, `total`, and `complete` for the enclosing callable's data dependencies. | Invalid/forbidden path or no enclosing callable. |
| `entry_points()` | Analysis: `entrypoints` and CLDK `coverage`. | Missing selected OWASP alert or analysis failure. |
| `read_file(path, start=None, end=None)` | Source access: file text or an inclusive line range. | Invalid range, missing file, or unauthorized path. |
| `search(pattern, path=None)` | Source access: regex matches as `file`, `line`, `text` objects. | Invalid regex or unauthorized path. |
| `edit(path, old, new)` | Editing: replace exactly one occurrence and return `status`, `diff`, and `checks` (`applies`, `touches_flagged_line`, `clean_rescan`). | Wrong file; missing alert metadata or baseline; empty `old`; `old` not occurring exactly once. |
| `rescan(path)` | Rescanning: Bandit 1.9.4 MEDIUM-or-higher alert objects for the selected file. | No alert selected, wrong file, or inaccessible file. |

Host-only controls are discovered by the staff driver but not offered to the
model: `set_alert(alert_id)` selects an alert and returns its ID and path;
`configure_alerts(alerts, pinned_root)` installs alert metadata and a baseline
and returns the configured count; `validate_evidence(evidence)` checks evidence
and returns `valid`. On OWASP, `set_alert` also accepts a bare case name such as
`BenchmarkTest00011`. The normal host configures alert metadata and baseline
before edits. A standalone driver using a bare case can test read/analysis
scope and forbidden edits without that setup; a permitted edit requires the
metadata and baseline. Unknown alerts and invalid evidence are refused.

Absolute paths, parent traversal, workspace escapes, withheld files, and
out-of-scope OWASP reads are refused. Server refusals are MCP tool errors;
malformed arguments can instead fail schema validation. Tool descriptions tell
the model how to use tools; they are not themselves access controls. OpenShell
provides a separate filesystem and network boundary.

