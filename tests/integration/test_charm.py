#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for the Wazuh Agent charm using pytest-operator."""

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    """Build the charm and deploy it."""
    charm = await ops_test.build_charm(".")
    assert charm, "Charm build failed"

    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        num_units=1,
        series="jammy",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="waiting", timeout=600
    )


async def test_agent_status_is_blocked_without_server(ops_test: OpsTest):
    """Without a Wazuh server relation, the agent should be blocked or waiting."""
    status = await ops_test.model.get_status()
    app_status = status.applications[APP_NAME]
    # Should be waiting (if not installed) or blocked (installed but no server)
    assert app_status.status.status in ("waiting", "blocked")


async def test_config_update(ops_test: OpsTest):
    """Config changes should be accepted."""
    await ops_test.model.applications[APP_NAME].set_config({
        "wazuh-agent-name": "test-agent-01",
        "wazuh-agent-group": "test-group",
    })
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="waiting", timeout=120
    )
    config = await ops_test.model.applications[APP_NAME].get_config()
    assert config["wazuh-agent-name"]["value"] == "test-agent-01"


async def test_actions_available(ops_test: OpsTest):
    """All defined actions should be available."""
    unit = ops_test.model.applications[APP_NAME].units[0]
    for action_name in ("start", "stop", "restart", "status", "reconnect"):
        action = await unit.run_action(action_name)
        result = await action.wait()
        # status should always succeed
        if action_name == "status":
            assert "service" in result.results
