#!/bin/sh
set -eu

headscale serve &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT INT TERM
until headscale users list >/dev/null 2>&1; do sleep 1; done
headscale users create e2e >/dev/null 2>&1 || true
headscale policy set --file /e2e/policy.hujson
user=$(headscale users list -o json | python3 -c 'import json,sys; print(next(x["id"] for x in json.load(sys.stdin) if x["name"] == "e2e"))')
for role in dns gateway1; do
  headscale preauthkeys create --user "$user" --reusable --expiration 1h --tags "tag:$role" -o json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])' >"/auth/$role"
done
touch /auth/ready
wait "$pid"
