#!/bin/sh
# Builds, runs, and always removes the disposable compose E2E tailnet.
set -eu
cd "$(dirname "$0")"
log_file=full_logs.log
monitor_pids=""
stop_monitors() {
    for pid in $monitor_pids; do
        kill "$pid" 2>/dev/null || true
    done
}
cleanup() {
    stop_monitors
    docker compose -f compose.yaml down --volumes --remove-orphans >>"$log_file" 2>&1 || true
}
trap cleanup EXIT INT TERM
# Build serially: Docker BuildKit can otherwise race while exporting the two
# identical domain-gateway build graphs under separate Compose service tags.
: >"$log_file"
COMPOSE_PARALLEL_LIMIT=1 docker compose -f compose.yaml build >>"$log_file" 2>&1
docker compose -f compose.yaml up --detach --no-build >>"$log_file" 2>&1

docker compose -f compose.yaml logs --follow --no-color --timestamps >>"$log_file" 2>&1 &
monitor_pids="$!"
client=$(docker compose -f compose.yaml ps -q client)
docker logs --follow "$client" &
monitor_pids="$monitor_pids $!"
for service in headscale upstream dns gateway denied gateway-dns; do
    container=$(docker compose -f compose.yaml ps -q "$service")
    docker logs --follow "$container" 2>&1 >/dev/null | sed "s/^/$service | /" &
    monitor_pids="$monitor_pids $!"
done

status=$(docker wait "$client")
exit "$status"
