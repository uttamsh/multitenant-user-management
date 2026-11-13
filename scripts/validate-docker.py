#!/usr/bin/env python3
"""Read-only Docker contracts. Resolved credentials are never printed.

Run from the project root; add --image after `docker compose build api`.
Uses only Python's standard library and the Docker CLI.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse


def command(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Docker command failed; check local configuration/access privately")
    return result.stdout


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    root = Path(__file__).resolve().parent.parent
    minor = re.search(r"(?m)^go (\d+\.\d+)\.", (root / "go.mod").read_text()).group(1)
    require(f"ARG GO_VERSION={minor}\n" in (root / "Dockerfile").read_text(),
            "Docker builder Go minor must match go.mod")
    config = json.loads(command(["docker", "compose", "--project-directory", str(root),
                                 "config", "--format", "json"]))
    api = config["services"]["api"]
    env = api["environment"]
    target = urlparse(env["DATABASE_URL"])
    require(target.hostname == "postgres" and (target.port or 5432) == 5432
            and target.path == "/multitenant", "Container database must use postgres:5432/multitenant")
    require(env["HTTP_ADDR"] == "0.0.0.0:8080", "Container listener must accept its published port")
    require(len(env.get("JWT_SECRET", "")) >= 32 and "REPLACE" not in env["JWT_SECRET"].upper(),
            "Configure a non-placeholder JWT secret privately")
    require(api["ports"] and all(p["host_ip"] == "127.0.0.1" and p["target"] == 8080 for p in api["ports"]),
            "API publication must be loopback only")
    require(api["depends_on"]["postgres"]["condition"] == "service_healthy",
            "API must wait for PostgreSQL readiness")
    require(api["read_only"] and "ALL" in api["cap_drop"]
            and "no-new-privileges:true" in api["security_opt"],
            "API runtime hardening missing")
    require(api["healthcheck"]["test"] == ["CMD", "/app/healthcheck"]
            and api["restart"] == "unless-stopped", "Health/restart configuration missing")
    postgres = config["services"]["postgres"]
    require(postgres["image"] == "postgres:16-alpine", "PostgreSQL image changed")
    require(any(v.get("source") == "postgres_data" and v["target"] == "/var/lib/postgresql/data"
                for v in postgres["volumes"]), "Existing PostgreSQL named volume missing")
    print("PASS: Go version, container DB hostname, loopback port, readiness dependency and runtime hardening")
    if "--image" in sys.argv[1:]:
        image = json.loads(command(["docker", "image", "inspect", api["image"]]))[0]["Config"]
        require(image["User"] == "65532:65532" and image["Entrypoint"] == ["/app/api"],
                "Image must run API directly as non-root")
        require(image["Healthcheck"]["Test"] == ["CMD", "/app/healthcheck"], "Image healthcheck missing")
        require(not any(v.startswith(("JWT_SECRET=", "DATABASE_URL=", "DOCKER_DATABASE_URL="))
                        for v in image["Env"]), "Image contains runtime configuration secrets")
        print("PASS: built image is non-root, has readiness healthcheck and no baked credential environment")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print command output/config or exception values from credential parsing.
        if isinstance(error, RuntimeError):
            print("FAIL:", str(error), file=sys.stderr)
        else:
            print("FAIL: configuration could not be validated; inspect it privately", file=sys.stderr)
        sys.exit(1)
