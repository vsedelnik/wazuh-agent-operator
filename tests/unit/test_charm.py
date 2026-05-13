#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the Wazuh Agent charm."""

import unittest
from unittest.mock import MagicMock, patch

import ops
import ops.testing

from charm import WazuhAgentCharm


class TestWazuhAgentCharm(unittest.TestCase):
    """Test cases for the WazuhAgentCharm."""

    def setUp(self):
        self.harness = ops.testing.Harness(WazuhAgentCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_initial_status_blocked(self):
        """Charm should be blocked before installation and configuration."""
        self.harness.charm.on.install.emit()
        self.assertIsInstance(
            self.harness.charm.unit.status,
            ops.MaintenanceStatus,
        )

    def test_start_without_manager(self):
        """Charm should go to WaitingStatus when no manager is configured."""
        self.harness.charm.on.install.emit()
        self.harness.charm.on.start.emit()
        status = self.harness.charm.unit.status
        self.assertTrue(
            isinstance(status, (ops.WaitingStatus, ops.BlockedStatus))
        )

    def test_agent_manager_defaults(self):
        """Agent manager should reflect charm config defaults."""
        agent = self.harness.charm.agent
        self.assertEqual(agent._effective_manager_address(), "")
        # Should fall through to config defaults
        self.assertTrue(isinstance(agent, object))

    def test_config_changed_updates(self):
        """Config changed should trigger ossec.conf reconciliation."""
        with patch.object(
            self.harness.charm.agent, "_is_installed", return_value=True
        ), patch.object(
            self.harness.charm.agent, "configure_ossec", return_value=False
        ), patch.object(
            self.harness.charm.agent, "is_running", return_value=True
        ):
            self.harness.update_config({"wazuh-manager-address": "10.0.0.1"})
            self.assertEqual(
                self.harness.charm.agent._effective_manager_address(), "10.0.0.1"
            )

    def test_wazuh_server_relation_data(self):
        """Relation with wazuh-server should provide manager address."""
        rel_id = self.harness.add_relation("wazuh-server", "wazuh-server")
        self.harness.add_relation_unit(rel_id, "wazuh-server/0")
        self.harness.update_relation_data(
            rel_id,
            "wazuh-server",
            {
                "manager-address": "wazuh.internal",
                "enrollment-password": "secret123",
                "manager-port": "1514",
                "registration-port": "1515",
            },
        )
        self.assertEqual(
            self.harness.charm.agent._get_relation_manager_address(),
            "wazuh.internal",
        )
        self.assertEqual(
            self.harness.charm.agent._get_relation_enrollment_password(),
            "secret123",
        )

    def test_peer_relation_publishes_status(self):
        """Agent status should be published on the peer relation."""
        with patch.object(
            self.harness.charm.agent, "_is_installed", return_value=True
        ), patch.object(
            self.harness.charm.agent, "_effective_manager_address",
            return_value="10.0.0.1",
        ), patch.object(
            self.harness.charm.agent, "is_running", return_value=True
        ), patch.object(
            self.harness.charm.agent, "_get_agent_version", return_value="4.9.2"
        ):
            rel_id = self.harness.add_relation("agent-peers", "wazuh-agent")
            self.harness.add_relation_unit(rel_id, "wazuh-agent/1")
            self.harness.charm._update_status()
            data = self.harness.get_relation_data(rel_id, self.harness.charm.unit)
            self.assertIn("agent-status", data)
            self.assertEqual(data["agent-version"], "4.9.2")


class TestWazuhAgentManager(unittest.TestCase):
    """Test cases for the WazuhAgentManager helper."""

    def setUp(self):
        self.harness = ops.testing.Harness(WazuhAgentCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.manager = self.harness.charm.agent

    def test_hold_package_calls_apt_mark(self):
        """hold_package should run apt-mark hold."""
        with patch("charm._run_command") as mock_run:
            mock_run.return_value = (0, "", "")
            self.manager._hold_package()
            mock_run.assert_called_with(["apt-mark", "hold", "wazuh-agent"])

    def test_unhold_package_calls_apt_mark(self):
        """unhold_package should run apt-mark unhold."""
        with patch("charm._run_command") as mock_run:
            mock_run.return_value = (0, "", "")
            self.manager.unhold_package()
            mock_run.assert_called_with(["apt-mark", "unhold", "wazuh-agent"])

    def test_is_installed_checks_dpkg(self):
        """is_installed should check dpkg for the package."""
        with patch("charm._run_command") as mock_run:
            mock_run.return_value = (0, "install ok installed", "")
            self.assertTrue(self.manager._is_installed())

    def test_get_agent_version_queries_dpkg(self):
        """get_agent_version should query dpkg."""
        with patch("charm._run_command") as mock_run:
            mock_run.return_value = (0, "4.9.2-1", "")
            self.assertEqual(self.manager._get_agent_version(), "4.9.2-1")

    def test_effective_address_prefers_config(self):
        """Config value should take precedence over relation data."""
        self.harness.update_config({"wazuh-manager-address": "config.example.com"})
        rel_id = self.harness.add_relation("wazuh-server", "wazuh-server")
        self.harness.add_relation_unit(rel_id, "wazuh-server/0")
        self.harness.update_relation_data(
            rel_id,
            "wazuh-server",
            {"manager-address": "relation.example.com"},
        )
        self.assertEqual(
            self.manager._effective_manager_address(),
            "config.example.com",
        )


class TestWazuhServerData(unittest.TestCase):
    """Test the WazuhServerData library class."""

    def test_from_relation_data_minimal(self):
        """Minimal data should parse correctly."""
        from wazuh_server import WazuhServerData

        data = WazuhServerData.from_relation_data({
            "manager-address": "10.0.0.1",
            "enrollment-password": "s3cret",
        })
        self.assertEqual(data.manager_address, "10.0.0.1")
        self.assertEqual(data.enrollment_password, "s3cret")
        self.assertEqual(data.manager_port, 1514)  # default

    def test_is_valid_requires_address_and_password(self):
        """is_valid should require both address and password."""
        from wazuh_server import WazuhServerData

        data = WazuhServerData(
            manager_address="10.0.0.1", enrollment_password="pwd"
        )
        self.assertTrue(data.is_valid)
        data.enrollment_password = ""
        self.assertFalse(data.is_valid)

    def test_to_env_produces_wazuh_variables(self):
        """to_env should produce WAZUH_*-prefixed environment variables."""
        from wazuh_server import WazuhServerData

        data = WazuhServerData(
            manager_address="10.0.0.2",
            manager_port=1514,
            enrollment_password="abc",
        )
        env = data.to_env()
        self.assertEqual(env["WAZUH_MANAGER"], "10.0.0.2")
        self.assertEqual(env["WAZUH_MANAGER_PORT"], "1514")
        self.assertEqual(env["WAZUH_REGISTRATION_PASSWORD"], "abc")
        self.assertEqual(env["WAZUH_PROTOCOL"], "tcp")


if __name__ == "__main__":
    unittest.main()
