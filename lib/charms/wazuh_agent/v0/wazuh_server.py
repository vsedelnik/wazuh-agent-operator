#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for consuming the `wazuh_server` relation interface.

This library lets a charm consume the `wazuh_server` interface, which
is provided by a Wazuh server charm (e.g., `wazuh-server-operator`).

The provider charm publishes:

- `manager-address`: IP or hostname of the Wazuh manager (required)
- `manager-port`: Manager communication port (default 1514)
- `registration-port`: Agent enrollment port (default 1515)
- `enrollment-password`: Password for agent enrollment (required)
- `protocol`: Communication protocol, `tcp` or `udp`
- `version`: Wazuh server version

### Usage

```python
from charms.wazuh_agent.v0.wazuh_server import WazuhServerConsumer, WazuhServerData

class MyCharm(ops.CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.server = WazuhServerConsumer(self)
        self.framework.observe(
            self.on["wazuh-server"].relation_changed,
            self._on_server_changed,
        )

    def _on_server_changed(self, event):
        if data := self.server.get_data():
            logger.info("Manager: %s", data.manager_address)
```
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import ops

__all__ = ["WazuhServerConsumer", "WazuhServerData"]

logger = logging.getLogger(__name__)

LIBID = "abc123wazuhserverv0"  # unique library identifier
LIBAPI = 0
LIBPATCH = 1

RELATION_NAME = "wazuh-server"

# Keys the provider publishes in its relation data
KEY_MANAGER_ADDRESS = "manager-address"
KEY_MANAGER_PORT = "manager-port"
KEY_REGISTRATION_PORT = "registration-port"
KEY_ENROLLMENT_PASSWORD = "enrollment-password"
KEY_PROTOCOL = "protocol"
KEY_VERSION = "version"


@dataclass
class WazuhServerData:
    """Structured data received from the Wazuh server relation."""

    manager_address: str
    manager_port: int = 1514
    registration_port: int = 1515
    enrollment_password: str = ""
    protocol: str = "tcp"
    version: str = ""

    @classmethod
    def from_relation_data(cls, data: dict) -> "WazuhServerData":
        """Construct from the raw relation application data bag."""
        return cls(
            manager_address=data.get(KEY_MANAGER_ADDRESS, ""),
            manager_port=int(data.get(KEY_MANAGER_PORT, 1514)),
            registration_port=int(data.get(KEY_REGISTRATION_PORT, 1515)),
            enrollment_password=data.get(KEY_ENROLLMENT_PASSWORD, ""),
            protocol=data.get(KEY_PROTOCOL, "tcp"),
            version=data.get(KEY_VERSION, ""),
        )

    @property
    def is_valid(self) -> bool:
        """Return True if the minimum required fields are present."""
        return bool(self.manager_address and self.enrollment_password)

    def to_env(self) -> dict[str, str]:
        """Return WAZUH_* environment variables for agent installation."""
        env = {
            "WAZUH_MANAGER": self.manager_address,
            "WAZUH_MANAGER_PORT": str(self.manager_port),
            "WAZUH_REGISTRATION_SERVER": self.manager_address,
            "WAZUH_REGISTRATION_PORT": str(self.registration_port),
            "WAZUH_REGISTRATION_PASSWORD": self.enrollment_password,
            "WAZUH_PROTOCOL": self.protocol,
        }
        return {k: v for k, v in env.items() if v}


class WazuhServerConsumer:
    """Consumer-side helper for the `wazuh_server` relation interface.

    Monitors the `wazuh-server` relation and extracts the data published
    by the provider (Wazuh server charm).
    """

    def __init__(self, charm: ops.CharmBase, relation_name: str = RELATION_NAME):
        self._charm = charm
        self._relation_name = relation_name

    @property
    def relation(self) -> Optional[ops.Relation]:
        """Return the active wazuh-server relation, if any."""
        return self._charm.model.get_relation(self._relation_name)

    @property
    def is_ready(self) -> bool:
        """Return True when the relation data is complete and usable."""
        data = self.get_data()
        return data is not None and data.is_valid

    def get_data(self) -> Optional[WazuhServerData]:
        """Return structured data from the provider, or None if unavailable."""
        rel = self.relation
        if not rel or not rel.app:
            return None
        raw = dict(rel.data.get(rel.app, {}))
        if not raw:
            return None
        return WazuhServerData.from_relation_data(raw)

    def get_manager_address(self) -> str:
        """Convenience: return the manager address or empty string."""
        data = self.get_data()
        return data.manager_address if data else ""

    def get_enrollment_password(self) -> str:
        """Convenience: return the enrollment password or empty string."""
        data = self.get_data()
        return data.enrollment_password if data else ""
