# Wazuh Agent Operator

A Juju charm for deploying and managing the [Wazuh Agent](https://wazuh.com/) on Ubuntu machines.

The Wazuh agent is a lightweight, multi-platform endpoint security agent that collects security event data, performs local integrity checks, and forwards results to the Wazuh server for analysis and threat detection.

## Features

- **One-line deployment** via Juju
- **Automatic enrollment** with a Wazuh server via relation integration
- **Comprehensive configuration**: manager address, enrollment, protocol, groups, keep-alive
- **Lifecycle actions**: start, stop, restart, status, show-config, reconnect, manual enrollment
- **Version pinning** to prevent accidental upgrades
- **Subordinate-ready**: can be deployed alongside any principal charm via `juju-info`

## Architecture

```
┌──────────────┐    wazuh-server    ┌──────────────────┐
│ Wazuh Server │ ◄────────────────► │  Wazuh Agent     │
│   Charm      │   (provides)       │    Charm         │
└──────────────┘                    │  (requires)      │
                                    │                  │
                                    │ • Installs agent │
                                    │ • Enrolls agent  │
                                    │ • Manages config │
                                    │ • Monitors svc   │
                                    └──────────────────┘
```

## Quick Start

### Prerequisites

- Juju 3.0+ controller
- A principal charm already deployed (e.g., `ubuntu`, `openstack-compute`, `kubernetes-worker`, `microcloud`)

### Deploy alongside a principal charm

```bash
# Deploy the Wazuh agent as a subordinate charm
juju deploy wazuh-agent

# Attach it to your principal charm (e.g., a Kubernetes worker)
juju integrate wazuh-agent:juju-info kubernetes-worker

# Integrate with a Wazuh server
juju integrate wazuh-agent wazuh-server
```

The agent installs on every machine where the principal charm runs.

### With Configuration

```bash
juju deploy wazuh-agent \
  --config wazuh-agent-name="web-server-01" \
  --config wazuh-agent-group="production,web" \
  --config wazuh-manager-address="wazuh.internal"
```

### Common principal charms

| Principal Charm | Use Case |
|-----------------|----------|
| `ubuntu` | Generic Ubuntu machines |
| `openstack-compute` | OpenStack compute nodes |
| `kubernetes-worker` | Kubernetes worker nodes |
| `microcloud` | MicroCloud nodes |

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `wazuh-manager-address` | string | `""` | Wazuh manager IP/hostname (comma-separated for HA) |
| `wazuh-manager-port` | int | `1514` | Manager communication port |
| `wazuh-protocol` | string | `tcp` | Protocol: `tcp` or `udp` |
| `wazuh-registration-address` | string | `""` | Enrollment server address |
| `wazuh-registration-port` | int | `1515` | Enrollment port |
| `wazuh-registration-password` | string | `""` | Enrollment password |
| `wazuh-agent-name` | string | `""` | Custom agent name |
| `wazuh-agent-group` | string | `""` | Agent group(s), comma-separated |
| `wazuh-keep-alive-interval` | int | `10` | Keep-alive check interval (seconds) |
| `wazuh-time-reconnect` | int | `30` | Reconnect wait after connection loss (seconds) |
| `disable-auto-updates` | bool | `true` | Pin package to prevent automatic upgrades |

## Actions

| Action | Description |
|--------|-------------|
| `start` | Start the Wazuh agent service |
| `stop` | Stop the Wazuh agent service |
| `restart` | Restart the Wazuh agent service |
| `status` | Show current agent status (service, version, manager, name) |
| `show-config` | Display the effective `ossec.conf` client configuration |
| `reconnect` | Force agent reconnection to the manager |
| `enroll-agent` | Manually enroll the agent (custom address, password, name, group) |

Example:

```bash
juju run wazuh-agent/0 status
juju run wazuh-agent/0 enroll-agent \
  manager-address="10.0.0.1" \
  registration-password="secret" \
  agent-name="custom-agent"
```

## Integration

### `wazuh-server` (requires)

Connects the agent to a Wazuh server charm. The server charm provides:

- `manager-address` — Wazuh manager IP/hostname
- `enrollment-password` — Enrollment password for agent registration
- `manager-port` — Manager communication port (default: 1514)
- `registration-port` — Registration port (default: 1515)
- `protocol` — Communication protocol (`tcp`/`udp`)
- `version` — Wazuh server version

The agent automatically configures itself and enrolls when this relation is established.

### `juju-info` (requires, optional)

For subordinate deployment. Integrate with any principal charm to deploy the agent alongside it on the same machine.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linting
tox -e lint

# Run unit tests
tox -e unit

# Run integration tests (requires Juju controller)
tox -e integration

# Build the charm
charmcraft pack
```

## Compatibility

- Juju ≥ 3.0
- Ubuntu 22.04 (Jammy), 24.04 (Noble), 26.04 (Resolute)
- Wazuh agent version ≤ Wazuh server version (Wazuh compatibility constraint)

### Building for multiple platforms

```bash
# Build for a specific Ubuntu release (requires charmcraft ≥ 4.0)
charmcraft pack --platform ubuntu@22.04:amd64
charmcraft pack --platform ubuntu@24.04:amd64
charmcraft pack --platform ubuntu@26.04:amd64

# Cross-build 22.04/24.04 from a 26.04 host via LXD
charmcraft pack --platform ubuntu@22.04:amd64 --use-lxd
```

## License

Apache 2.0 — See [LICENSE](LICENSE).

## Links

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Juju Documentation](https://juju.is/docs)
- [Charm Development](https://documentation.ubuntu.com/ops/)
- [Charmhub](https://charmhub.io/)
