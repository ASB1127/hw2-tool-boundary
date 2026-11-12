# hw2-tool-boundary

COMS E6998-019 HW2: extend your HW1 agent into two agents over CLDK 2.0, a
code-action agent and an MCP agent, run both inside an OpenShell sandbox, and
measure how they behave under a planted injection. The assignment is in
[briefs/hw2.pdf](briefs/hw2.pdf) (source: `briefs/hw2.tex`).

There is no starter code. You design and write every part of both agents and the
server.

## Building the brief

With Tectonic and Pygments (`pygmentize`) on `PATH`, run:

```bash
cd briefs
tectonic -X compile -Z shell-escape -Z shell-escape-cwd=. hw2.tex
```

For LaTeX Workshop, configure a Tectonic recipe in `.vscode/settings.json` at
the root of the folder opened in VS Code. Settings in `briefs/.vscode/` apply
only when `briefs/` itself is the opened workspace, not when the repository
root is open. Enable shell escape for `minted`, set its working directory to
`%DIR%`, and ensure the recipe's `PATH` selects a working `pygmentize`.

## Repository contents

| File | What it is |
|---|---|
| `briefs/hw2.pdf` | The assignment brief |
| `config.schema.json` | JSON Schema the config your agent reads (`--config`, TOML) must validate against: HW1's keys plus `[agent] kind`, `[mcp] config` and `[sandbox] policy` |
| `report.schema.json` | JSON Schema your `report.json` must validate against: each row gains `remediation` |
| `trace.schema.json` | JSON Schema each line of your `trace.jsonl` must validate against: `via`, `refused_by` and the `discovery` kind are new, and a valid HW1 trace line stays valid |

Examples, in `examples/`:

- `config.example.toml`: a valid config for OWASP BenchmarkPython.
- `mcp.example.json`: how `mcp.json` starts a server.
- `policy.example.yaml`: an OpenShell policy for the Anthropic API.
- `policy.local.yaml`: the same policy with a `tcp` grant to an OpenAI-compatible model server on your own machine.
- `report.example.json`: an example `report.json`, 3 of the 18 OWASP rows, showing the format (rationales are placeholders).
- `trace.example.jsonl`: an example trajectory on one alert showing `via`, `refused_by` and `discovery`; it is not the run behind `report.example.json`.

Fixtures, in `fixtures/`: `injection.patch` is the planted injection for the live
runs, and `fixtures/README.md` says how to apply and remove it.

Build the sandbox image from your repository first, with each target at
`/target`, and register the Anthropic provider (brief, Section 9.1 gives both).
Then the two launch commands, abridged from the brief and shown for OWASP:
create the sandbox from your image and policy, then copy the granted entries of
the target into `/sandbox/work` and run your agent on the copy, with its config
already at `/sandbox/work/config.toml`.

```bash
openshell sandbox create --name <name> --from <image> --policy policy.yaml \
    --provider anthropic --detach -- sleep infinity
openshell sandbox exec -n <name> --no-login-shell --no-tty -- sh -c '
  mkdir -p /sandbox/work/target &&
  cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ &&
  your-agent --input /sandbox/work/target --output /sandbox/work/run --config /sandbox/work/config.toml'
```

For a model server on your own machine, create with `examples/policy.local.yaml`
as the policy, `--no-auto-providers` in place of `--provider anthropic`, and the
server's address in `exec --env`. Your own `README.md` must tell us how to run
both agents end to end, with `configs/mcp.toml` and `configs/codeact.toml` (brief,
Section 9).

## Remediation outcomes

A validated label-1 alert enters remediation. If the model returns `edited`, the
runner computes the diff and runs all three acceptance checks; the report records
`accepted` or `rejected`. If it returns `not_edited`, no patch exists to check, so
the report records `skipped` with an empty diff, null checks, and the model's
`summary` as an extra field. Label-0 and unclassified alerts are also `skipped`.
