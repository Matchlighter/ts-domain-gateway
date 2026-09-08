#!/usr/bin/env python3
"""Run the disposable Docker E2E tailnet from one deterministic coordinator."""

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
COMPOSE_FILE = HERE / "compose.yaml"
POLICY_FILE = HERE / "compose-policy.hujson"
PROJECT = "domain-gateway-e2e2"


def compose(*args, capture=False):
    command = ["docker", "compose", "--project-name", PROJECT, "--file", str(COMPOSE_FILE), *args]
    print("E2E:", " ".join(command), flush=True)
    return subprocess.run(command, text=True, check=True, capture_output=capture)


def wait_for(name, command, timeout=90):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return command()
        except (subprocess.CalledProcessError, ValueError, KeyError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(1)
    raise RuntimeError("timed out waiting for %s: %s" % (name, last_error))


def headscale(*args, capture=False):
    return compose("exec", "-T", "headscale", "headscale", *args, capture=capture)


def apply_policy():
    """Install the fixture policy through Headscale, as production updates do."""
    compose("cp", str(POLICY_FILE), "headscale:/tmp/e2e-policy.hujson")
    headscale("policy", "set", "--file", "/tmp/e2e-policy.hujson")


def user_id():
    users = json.loads(headscale("users", "list", "--output", "json", capture=True).stdout)
    return next(user["id"] for user in users if user["name"] == "e2e")


def base_nodes_ready():
    nodes = json.loads(headscale("nodes", "list", "--output", "json", capture=True).stdout)
    names = {node["givenName"] for node in nodes}
    if not {"e2e-dns", "e2e-gateway"} <= names:
        raise ValueError("base nodes have not enrolled: %s" % names)


def auth_key(tag):
    result = headscale(
        "preauthkeys", "create", "--user", str(user_id()), "--reusable", "--expiration", "1h",
        "--tags", tag, "--output", "json", capture=True,
    )
    return json.loads(result.stdout)["key"]


def run_with_client(tag, probe):
    """Run one fresh userspace client after its tagged node has joined the tailnet."""
    name = "e2e-%s-%s" % (tag.removeprefix("tag:"), secrets.token_hex(3))
    compose(
        "run", "--rm", "-e", "AUTH_KEY=" + auth_key(tag), "-e", "CLIENT_NAME=" + name,
        "client", "python3", "/e2e/client.py", probe,
    )


def main():
    # The build is deliberately serialized: the DNS and gateway images share
    # one build graph, and concurrent exports have raced in Docker BuildKit.
    environment = os.environ | {"COMPOSE_PARALLEL_LIMIT": "1"}
    subprocess.run(
        ["docker", "compose", "--project-name", PROJECT, "--file", str(COMPOSE_FILE), "build"],
        check=True, env=environment,
    )
    compose("up", "--detach", "--no-build")
    wait_for("Headscale user", user_id)
    apply_policy()
    wait_for("DNS and gateway enrollment", base_nodes_ready)

    # An authorized query creates the allocation before the denied lookup,
    # proving that authorization is evaluated at query time rather than merely
    # by whether a synthetic address already exists.
    run_with_client("tag:client", "authorized")
    run_with_client("tag:denied", "denied")
    run_with_client("tag:gateway1", "gateway-dns")


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        try:
            compose("logs", "--no-color")
        except subprocess.CalledProcessError:
            pass
        raise
    finally:
        try:
            compose("down", "--volumes", "--remove-orphans")
        except subprocess.CalledProcessError:
            pass
