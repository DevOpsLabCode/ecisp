"""Entrypoint: `python -m app`. Reads configuration from the environment
only -- no command-line flags, no config file -- so the Dockerfile's CMD
and any deployment (ECS task def, Kubernetes-for-*this*-component's-own-
control-plane if ever run that way, systemd unit) all configure it the
same way, by setting environment variables.
"""

from __future__ import annotations

import logging
import os
import sys

import boto3

from .backend_client import GolemBackendClient
from .responder import DEFAULT_ROLE_TEMPLATE, run_forever


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

    backend_url = os.environ.get("BACKEND_URL")
    api_key = os.environ.get("IAM_RESPONDER_API_KEY")
    if not backend_url or not api_key:
        print("BACKEND_URL and IAM_RESPONDER_API_KEY are both required", file=sys.stderr)
        raise SystemExit(1)

    role_template = os.environ.get("GOLEM_ASSUME_ROLE_TEMPLATE", DEFAULT_ROLE_TEMPLATE)
    poll_interval_seconds = float(os.environ.get("POLL_INTERVAL_SECONDS", "10"))

    backend = GolemBackendClient(backend_url, api_key)
    # A fresh STS client per poll cycle (see responder.run_forever) --
    # boto3's default credential chain (env vars, instance/task/pod role,
    # ~/.aws/credentials) picks up this component's own AWS identity,
    # never anything passed on the command line.
    run_forever(backend, lambda: boto3.client("sts"), role_template, poll_interval_seconds)


if __name__ == "__main__":
    main()
