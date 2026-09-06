#!/bin/sh
# Builds, runs, and always removes the disposable compose E2E tailnet.
set -eu
cd "$(dirname "$0")"
cleanup() { docker compose -f compose.yaml down --volumes --remove-orphans; }
trap cleanup EXIT INT TERM
# Build serially: Docker BuildKit can otherwise race while exporting the two
# identical domain-gateway build graphs under separate Compose service tags.
COMPOSE_PARALLEL_LIMIT=1 docker compose -f compose.yaml build
docker compose -f compose.yaml up --no-build --abort-on-container-exit --exit-code-from client
