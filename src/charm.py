#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh Agent machine charm."""

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

import ops
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

logger = logging.getLogger(__name__)

# ---- Constants ----

WAZUH_AGENT_SERVICE = "wazuh-agent"
WAZUH_GPG_KEY_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
WAZUH_KEYRING_PATH = "/usr/share/keyrings/wazuh.gpg"
WAZUH_SOURCES_LIST = "/etc/apt/sources.list.d/wazuh.list"
WAZUH_OSSEC_CONF = "/var/ossec/etc/ossec.conf"
WAZUH_CLIENT_KEYS = "/var/ossec/etc/client.keys"
WAZUH_AGENT_STATE_FILE = "/var/ossec/var/run/wazuh-agentd.state"

# Default package hold to prevent upgrades
DPKG_SELECTIONS_FILE = "/var/lib/dpkg/info/wazuh-agent.list"

PEER_RELATION_NAME = "agent-peers"

# Possible service statuses
SERVICE_RUNNING = "running"
SERVICE_STOPPED = "stopped"
SERVICE_UNKNOWN = "unknown"


def _run_command(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError as e:
        return -1, "", str(e)


def _check_and_install_package(package: str) -> bool:
    """Install an APT package if missing. Returns True if installed/already present."""
    rc, stdout, _ = _run_command(["dpkg", "-s", package])
    if rc == 0:
        return True
    logger.info("Installing prerequisite package: %s", package)
    rc, _, stderr = _run_command(["apt-get", "install", "-y", package])
    return rc == 0


def _service_is_running(service: str = WAZUH_AGENT_SERVICE) -> bool:
    """Check if the systemd service is active."""
    rc, stdout, _ = _run_command(["systemctl", "is-active", service])
    return rc == 0 and stdout == "active"


def _service_status(service: str = WAZUH_AGENT_SERVICE) -> str:
    """Return the systemd service status string."""
    if _service_is_running(service):
        return SERVICE_RUNNING
    rc, stdout, _ = _run_command(["systemctl", "is-active", service])
    if stdout == "inactive":
        return SERVICE_STOPPED
    return SERVICE_UNKNOWN


# ---- Wazuh Agent Manager ----


class WazuhAgentManager:
    """Handles Wazuh agent installation, configuration, and lifecycle."""

    def __init__(self, charm: ops.CharmBase):
        self._charm = charm

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

    def install(self) -> None:
        """Install the Wazuh agent from the official APT repository."""
        if self._is_installed():
            logger.info("Wazuh agent is already installed; skipping installation.")
            return

        logger.info("Installing Wazuh agent prerequisites…")
        _check_and_install_package("gnupg")
        _check_and_install_package("apt-transport-https")
        _check_and_install_package("curl")

        logger.info("Adding Wazuh GPG key…")
        _run_command(
            [
                "bash",
                "-c",
                f"curl -s {WAZUH_GPG_KEY_URL} | "
                f"gpg --no-default-keyring "
                f"--keyring gnupg-ring:{WAZUH_KEYRING_PATH} "
                f"--import && chmod 644 {WAZUH_KEYRING_PATH}",
            ]
        )

        repo_url = self._charm.config.get("wazuh-repository-url", "https://packages.wazuh.com/4.x/apt/")
        logger.info("Adding Wazuh APT repository: %s", repo_url)
        Path(WAZUH_SOURCES_LIST).parent.mkdir(parents=True, exist_ok=True)
        Path(WAZUH_SOURCES_LIST).write_text(
            f"deb [signed-by={WAZUH_KEYRING_PATH}] {repo_url} stable main\n"
        )

        logger.info("Updating APT cache…")
        _run_command(["apt-get", "update"])

        logger.info("Installing wazuh-agent package…")
        self._install_package()

        if self._charm.config.get("disable-auto-updates", True):
            self._hold_package()

    def _is_installed(self) -> bool:
        """Return True if wazuh-agent is installed."""
        rc, _, _ = _run_command(["dpkg", "-s", "wazuh-agent"])
        return rc == 0

    def _install_package(self) -> None:
        """Run apt-get install for wazuh-agent with optional enrollment vars."""
        env = os.environ.copy()
        self._set_env_if_set(env, "WAZUH_MANAGER", self._effective_manager_address())
        self._set_env_if_set(env, "WAZUH_MANAGER_PORT", str(self._charm.config.get("wazuh-manager-port", 1514)))

        registration_addr = self._effective_registration_address()
        if registration_addr:
            env["WAZUH_REGISTRATION_SERVER"] = registration_addr
        self._set_env_if_set(env, "WAZUH_REGISTRATION_PORT",
                             str(self._charm.config.get("wazuh-registration-port", 1515)))
        self._set_env_if_set(env, "WAZUH_REGISTRATION_PASSWORD",
                             self._charm.config.get("wazuh-registration-password", ""))
        self._set_env_if_set(env, "WAZUH_AGENT_NAME",
                             self._charm.config.get("wazuh-agent-name", ""))
        self._set_env_if_set(env, "WAZUH_AGENT_GROUP",
                             self._charm.config.get("wazuh-agent-group", ""))
        self._set_env_if_set(env, "WAZUH_PROTOCOL",
                             self._charm.config.get("wazuh-protocol", "tcp"))
        self._set_env_if_set(env, "WAZUH_KEEP_ALIVE_INTERVAL",
                             str(self._charm.config.get("wazuh-keep-alive-interval", 10)))
        self._set_env_if_set(env, "WAZUH_TIME_RECONNECT",
                             str(self._charm.config.get("wazuh-time-reconnect", 30)))

        # Filter out empty values (WAZUH_* variables must be non-empty)
        env = {k: v for k, v in env.items() if not k.startswith("WAZUH_") or v}

        logger.info("Running apt-get install with environment variables")
        result = subprocess.run(
            ["apt-get", "install", "-y", "wazuh-agent"],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.error("Failed to install wazuh-agent: %s", result.stderr)
            raise RuntimeError(f"Failed to install wazuh-agent: {result.stderr}")

        # Reload systemd and enable the service
        _run_command(["systemctl", "daemon-reload"])
        _run_command(["systemctl", "enable", WAZUH_AGENT_SERVICE])

    def _hold_package(self) -> None:
        """Pin the wazuh-agent package to prevent accidental upgrades."""
        logger.info("Holding wazuh-agent package at current version.")
        _run_command(["apt-mark", "hold", "wazuh-agent"])

    def unhold_package(self) -> None:
        """Remove the package hold."""
        logger.info("Unholding wazuh-agent package.")
        _run_command(["apt-mark", "unhold", "wazuh-agent"])

    @staticmethod
    def _set_env_if_set(env: dict, key: str, value: str) -> None:
        """Add to env dict if value is truthy (non-empty, non-zero)."""
        if value:
            env[key] = value

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _effective_manager_address(self) -> str:
        """Determine the Wazuh manager address from config or relation."""
        cfg_addr = self._charm.config.get("wazuh-manager-address", "")
        if cfg_addr:
            return cfg_addr
        # Try from relation data
        return self._get_relation_manager_address()

    def _effective_registration_address(self) -> str:
        """Determine the registration server address."""
        cfg_addr = self._charm.config.get("wazuh-registration-address", "")
        if cfg_addr:
            return cfg_addr
        return self._effective_manager_address()

    def _get_relation_manager_address(self) -> str:
        """Extract manager address from the wazuh-server relation data."""
        rel = self._charm.model.get_relation("wazuh-server")
        if not rel or not rel.app:
            return ""
        data = rel.data.get(rel.app, {})
        return data.get("manager-address", "")

    def _get_relation_enrollment_password(self) -> str:
        """Extract enrollment password from the wazuh-server relation data."""
        rel = self._charm.model.get_relation("wazuh-server")
        if not rel or not rel.app:
            return ""
        data = rel.data.get(rel.app, {})
        return data.get("enrollment-password", "")

    def configure_ossec(self) -> bool:
        """Update ossec.conf with current configuration.

        Returns True if the configuration changed and a restart is needed.
        """
        manager_addr = self._effective_manager_address()
        manager_port = self._charm.config.get("wazuh-manager-port", 1514)
        protocol = self._charm.config.get("wazuh-protocol", "tcp")

        if not manager_addr:
            logger.warning("No Wazuh manager address configured; skipping ossec.conf update.")
            return False

        if not Path(WAZUH_OSSEC_CONF).exists():
            logger.warning("ossec.conf does not exist yet; skipping update.")
            return False

        # Parse and update ossec.conf XML
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            logger.error("xml.etree.ElementTree unavailable; cannot update ossec.conf.")
            return False

        tree = ET.parse(WAZUH_OSSEC_CONF)
        root = tree.getroot()

        changed = False

        # Update client > server > address
        client = root.find("client")
        if client is not None:
            for server in client.findall("server"):
                addr_elem = server.find("address")
                if addr_elem is not None and addr_elem.text != manager_addr:
                    addr_elem.text = manager_addr
                    changed = True
                    logger.info("Updated manager address: %s", manager_addr)

                port_elem = server.find("port")
                if port_elem is not None and port_elem.text != str(manager_port):
                    port_elem.text = str(manager_port)
                    changed = True
                    logger.info("Updated manager port: %s", manager_port)

                proto_elem = server.find("protocol")
                if proto_elem is not None and proto_elem.text != protocol:
                    proto_elem.text = protocol
                    changed = True
                    logger.info("Updated protocol: %s", protocol)

        # Update enrollment section
        enrollment_addr = self._effective_registration_address()
        enrollment_port = str(self._charm.config.get("wazuh-registration-port", 1515))
        enrollment_pwd = self._charm.config.get("wazuh-registration-password", "") or self._get_relation_enrollment_password()
        agent_name = self._charm.config.get("wazuh-agent-name", "")
        agent_group = self._charm.config.get("wazuh-agent-group", "")

        if client is not None:
            enrollment = client.find("enrollment")
            if enrollment is not None:
                mgr_elem = enrollment.find("manager_address")
                if mgr_elem is not None and mgr_elem.text != enrollment_addr:
                    mgr_elem.text = enrollment_addr
                    changed = True

                port_elem = enrollment.find("port")
                if port_elem is not None and port_elem.text != enrollment_port:
                    port_elem.text = enrollment_port
                    changed = True

                auth_pass = enrollment.find("authorization_pass_path")
                if auth_pass is not None and enrollment_pwd:
                    # Write the password to authd.pass and update the path
                    auth_pass_path = "/var/ossec/etc/authd.pass"
                    Path(auth_pass_path).write_text(enrollment_pwd)
                    auth_pass.text = auth_pass_path
                    changed = True

                agent_name_elem = enrollment.find("agent_name")
                if agent_name_elem is not None and agent_name and agent_name_elem.text != agent_name:
                    agent_name_elem.text = agent_name
                    changed = True
                elif agent_name_elem is None and agent_name:
                    elem = ET.SubElement(enrollment, "agent_name")
                    elem.text = agent_name
                    changed = True

                agent_group_elem = enrollment.find("agent_groups")
                if agent_group_elem is not None and agent_group and agent_group_elem.text != agent_group:
                    agent_group_elem.text = agent_group
                    changed = True
                elif agent_group_elem is None and agent_group:
                    elem = ET.SubElement(enrollment, "agent_groups")
                    elem.text = agent_group
                    changed = True

        # Write back if changed
        if changed:
            tree.write(WAZUH_OSSEC_CONF, encoding="utf-8", xml_declaration=True)
            logger.info("ossec.conf updated successfully.")

        return changed

    # ------------------------------------------------------------------
    # Service lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Wazuh agent service."""
        _run_command(["systemctl", "start", WAZUH_AGENT_SERVICE])

    def stop(self) -> None:
        """Stop the Wazuh agent service."""
        _run_command(["systemctl", "stop", WAZUH_AGENT_SERVICE])

    def restart(self) -> None:
        """Restart the Wazuh agent service."""
        _run_command(["systemctl", "restart", WAZUH_AGENT_SERVICE])

    def reload(self) -> None:
        """Reload the Wazuh agent service configuration (graceful)."""
        _run_command(["systemctl", "reload-or-restart", WAZUH_AGENT_SERVICE])

    @property
    def is_running(self) -> bool:
        """Return True if the agent service is running."""
        return _service_is_running()

    @property
    def status_text(self) -> str:
        """Return a human-readable status string."""
        return _service_status()

    def get_agent_info(self) -> dict:
        """Collect agent info for status/actions."""
        info = {
            "service": _service_status(),
            "installed": self._is_installed(),
            "version": self._get_agent_version(),
            "manager-address": self._effective_manager_address(),
            "agent-name": self._charm.config.get("wazuh-agent-name", "") or os.uname().nodename,
        }
        return info

    def _get_agent_version(self) -> str:
        """Get the installed wazuh-agent version."""
        rc, stdout, _ = _run_command(
            ["dpkg-query", "-W", "-f=${Version}", "wazuh-agent"]
        )
        return stdout if rc == 0 else "unknown"

    def enroll_agent(
        self,
        manager_address: Optional[str] = None,
        registration_password: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_group: Optional[str] = None,
    ) -> str:
        """Manually enroll the agent using agent-auth."""
        auth_bin = "/var/ossec/bin/agent-auth"
        if not Path(auth_bin).exists():
            return "agent-auth binary not found. Is the Wazuh agent installed?"

        addr = manager_address or self._effective_manager_address()
        if not addr:
            return "No manager address configured. Set wazuh-manager-address or integrate with wazuh-server."

        password = registration_password or self._charm.config.get("wazuh-registration-password", "")
        if not password:
            password = self._get_relation_enrollment_password()
        if not password:
            return "No enrollment password configured. Set wazuh-registration-password or integrate with wazuh-server."

        cmd = [auth_bin, "-m", addr, "-P", password]
        name = agent_name or self._charm.config.get("wazuh-agent-name", "")
        if name:
            cmd += ["-A", name]
        group = agent_group or self._charm.config.get("wazuh-agent-group", "")
        if group:
            cmd += ["-G", group]

        port = str(self._charm.config.get("wazuh-registration-port", 1515))
        cmd += ["-p", port]

        rc, stdout, stderr = _run_command(cmd, timeout=30)
        if rc == 0:
            logger.info("Agent enrolled successfully: %s", stdout)
            return f"Enrollment successful: {stdout}"
        else:
            logger.error("Agent enrollment failed: %s", stderr)
            return f"Enrollment failed (rc={rc}): {stderr}"

    def show_config(self) -> str:
        """Return contents of ossec.conf (client section)."""
        try:
            import xml.etree.ElementTree as ET

            tree = ET.parse(WAZUH_OSSEC_CONF)
            client = tree.find("client")
            if client is not None:
                ET.indent(client, space="  ")
                return ET.tostring(client, encoding="unicode")
            return "No <client> section found in ossec.conf"
        except Exception as e:
            return f"Error reading ossec.conf: {e}"


# ---- Charm ----


class WazuhAgentCharm(ops.CharmBase):
    """Charm for deploying and managing the Wazuh agent."""

    def __init__(self, *args):
        super().__init__(*args)
        self.agent = WazuhAgentManager(self)

        # Core lifecycle hooks
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.update_status, self._on_update_status)

        # Relations
        self.framework.observe(
            self.on["wazuh-server"].relation_changed, self._on_wazuh_server_changed
        )
        self.framework.observe(
            self.on["wazuh-server"].relation_broken, self._on_wazuh_server_broken
        )

        # Actions
        self.framework.observe(self.on.start_action, self._on_start_action)
        self.framework.observe(self.on.stop_action, self._on_stop_action)
        self.framework.observe(self.on.restart_action, self._on_restart_action)
        self.framework.observe(self.on.status_action, self._on_status_action)
        self.framework.observe(self.on.show_config_action, self._on_show_config_action)
        self.framework.observe(self.on.reconnect_action, self._on_reconnect_action)
        self.framework.observe(self.on.enroll_agent_action, self._on_enroll_agent_action)

    # ------------------------------------------------------------------
    # Lifecycle events
    # ------------------------------------------------------------------

    def _on_install(self, event: ops.InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus("Installing Wazuh agent…")
        try:
            self.agent.install()
            self.unit.status = MaintenanceStatus("Wazuh agent installed.")
        except Exception as e:
            logger.error("Installation failed: %s", e)
            self.unit.status = BlockedStatus(f"Installation failed: {e}")
            event.defer()
            return

    def _on_start(self, event: ops.StartEvent) -> None:
        """Handle the start event."""
        if not self.agent._is_installed():
            self.unit.status = BlockedStatus("Wazuh agent not installed")
            return

        manager = self.agent._effective_manager_address()
        if not manager:
            self.unit.status = WaitingStatus("Waiting for Wazuh server relation or config")
            return

        self.unit.status = MaintenanceStatus("Starting Wazuh agent…")
        try:
            self.agent.configure_ossec()
            self.agent.start()
            if self.agent.is_running:
                self.unit.status = ActiveStatus("Agent running")
            else:
                self.unit.status = BlockedStatus("Agent failed to start")
        except Exception as e:
            logger.error("Start failed: %s", e)
            self.unit.status = BlockedStatus(f"Start failed: {e}")

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle the stop event."""
        if self.agent._is_installed():
            self.agent.stop()

    def _on_remove(self, _: ops.RemoveEvent) -> None:
        """Handle the remove event."""
        logger.info("Removing Wazuh agent…")
        if self.agent._is_installed():
            self.agent.stop()
            _run_command(["apt-get", "remove", "-y", "wazuh-agent"])
            Path(WAZUH_SOURCES_LIST).unlink(missing_ok=True)

    def _on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        """Handle config-changed events."""
        if not self.agent._is_installed():
            self.unit.status = BlockedStatus("Wazuh agent not installed")
            return

        changed = self.agent.configure_ossec()
        if changed and self.agent.is_running:
            self.agent.restart()
            logger.info("Agent restarted after configuration change.")

        self._update_status()

    def _on_update_status(self, _: ops.UpdateStatusEvent) -> None:
        """Periodic status update."""
        self._update_status()

    # ------------------------------------------------------------------
    # Relation events
    # ------------------------------------------------------------------

    def _on_wazuh_server_changed(self, event: ops.RelationChangedEvent) -> None:
        """Handle new/changed data from the Wazuh server relation."""
        logger.info("Wazuh server relation data received.")
        if not self.agent._is_installed():
            self.unit.status = BlockedStatus("Wazuh agent not installed")
            event.defer()
            return

        # Check if enrollment is needed
        manager = self.agent._effective_manager_address()
        if not Path(WAZUH_CLIENT_KEYS).exists() and manager:
            logger.info("Agent not yet enrolled. Attempting enrollment…")
            self.unit.status = MaintenanceStatus("Enrolling agent with Wazuh server…")
            result = self.agent.enroll_agent()
            logger.info("Enrollment result: %s", result)

        self.agent.configure_ossec()
        if self.agent.is_running:
            self.agent.restart()
        else:
            self.agent.start()

        self._update_status()

    def _on_wazuh_server_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle Wazuh server relation removal."""
        logger.warning("Wazuh server relation removed. Agent will retain last configuration.")
        self.unit.status = BlockedStatus("Wazuh server relation removed")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_start_action(self, event: ops.ActionEvent) -> None:
        """Action: start the agent."""
        if not self.agent._is_installed():
            event.fail("Wazuh agent is not installed.")
            return
        self.agent.start()
        time.sleep(2)
        if self.agent.is_running:
            event.set_results({"status": "started", "message": "Wazuh agent started successfully."})
        else:
            event.fail("Failed to start Wazuh agent.")

    def _on_stop_action(self, event: ops.ActionEvent) -> None:
        """Action: stop the agent."""
        if not self.agent._is_installed():
            event.fail("Wazuh agent is not installed.")
            return
        self.agent.stop()
        time.sleep(2)
        if not self.agent.is_running:
            event.set_results({"status": "stopped", "message": "Wazuh agent stopped successfully."})
        else:
            event.fail("Failed to stop Wazuh agent.")

    def _on_restart_action(self, event: ops.ActionEvent) -> None:
        """Action: restart the agent."""
        if not self.agent._is_installed():
            event.fail("Wazuh agent is not installed.")
            return
        self.agent.restart()
        time.sleep(3)
        if self.agent.is_running:
            event.set_results({"status": "restarted", "message": "Wazuh agent restarted successfully."})
        else:
            event.fail("Failed to restart Wazuh agent.")

    def _on_status_action(self, event: ops.ActionEvent) -> None:
        """Action: report agent status."""
        info = self.agent.get_agent_info()
        event.set_results(info)

    def _on_show_config_action(self, event: ops.ActionEvent) -> None:
        """Action: show the current ossec.conf client configuration."""
        config = self.agent.show_config()
        event.set_results({"config": config})

    def _on_reconnect_action(self, event: ops.ActionEvent) -> None:
        """Action: force reconnect to the Wazuh manager."""
        if not self.agent._is_installed():
            event.fail("Wazuh agent is not installed.")
            return
        self.agent.restart()
        time.sleep(3)
        event.set_results({"status": "reconnected", "message": "Agent restarted to force reconnection."})

    def _on_enroll_agent_action(self, event: ops.ActionEvent) -> None:
        """Action: manually enroll the agent."""
        if not self.agent._is_installed():
            event.fail("Wazuh agent is not installed.")
            return
        manager = event.params.get("manager-address", None)
        password = event.params.get("registration-password", None)
        name = event.params.get("agent-name", None)
        group = event.params.get("agent-group", None)
        result = self.agent.enroll_agent(
            manager_address=manager,
            registration_password=password,
            agent_name=name,
            agent_group=group,
        )
        event.set_results({"result": result})
        # Update config after enrollment
        self.agent.configure_ossec()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_status(self) -> None:
        """Set the Juju unit status based on current agent state."""
        if not self.agent._is_installed():
            self.unit.status = BlockedStatus("Wazuh agent not installed")
            return

        manager = self.agent._effective_manager_address()
        if not manager:
            self.unit.status = WaitingStatus("Waiting for Wazuh server configuration")
            return

        if self.agent.is_running:
            version = self.agent._get_agent_version()
            self.unit.status = ActiveStatus(f"Agent v{version} connected to {manager}")
        else:
            self.unit.status = BlockedStatus("Agent service is not running")

        # Publish agent info on peer relation for subordinate principals
        self._publish_agent_info()

    def _publish_agent_info(self) -> None:
        """Share agent status with peer units."""
        peer = self.model.get_relation(PEER_RELATION_NAME)
        if peer:
            peer.data[self.unit]["agent-status"] = self.agent.status_text
            peer.data[self.unit]["agent-version"] = self.agent._get_agent_version()


if __name__ == "__main__":
    ops.main(WazuhAgentCharm)