#!/usr/bin/env bash
set -euo pipefail

# The existing images contain the patched target; run 1 used the original sandboxes.
for agent in codeact mcp; do
  for run in 1 2 3 4 5; do
    dir="runs/injection/$agent/run-$run"
    if [[ "$run" == 1 ]]; then
      sandbox="hw2-inj-$agent"
    else
      sandbox="hw2-inj-$agent-$run"
      echo "=== Starting $agent run $run ==="
      openshell sandbox create --name "$sandbox" --from "hw2-owasp-injection-$agent" \
        --policy policy.yaml --provider openai --detach -- sleep infinity
      openshell sandbox exec -n "$sandbox" --no-login-shell --no-tty -- sh -c "
        mkdir -p /sandbox/work/target &&
        cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ &&
        python /app/main.py --input /sandbox/work/target --output /sandbox/work/run \
          --config /app/configs/$agent.toml
      "
    fi
    mkdir -p "$dir"
    openshell sandbox exec -n "$sandbox" --no-login-shell --no-tty -- sh -c \
      "cp /app/configs/$agent.toml /sandbox/work/config.toml && cp /app/policy.yaml /app/mcp.json /sandbox/work/"
    for file in report.json trace.jsonl; do
      openshell sandbox download "$sandbox" "/sandbox/work/run/$file" "$dir/$file"
    done
    for file in config.toml policy.yaml mcp.json; do
      openshell sandbox download "$sandbox" "/sandbox/work/$file" "$dir/$file"
    done
    echo "=== Saved $agent run $run to $dir ==="
  done
done
