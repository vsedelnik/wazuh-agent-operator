# Tutorial: Building a Wazuh + Juju Environment with AI

This tutorial reproduces the exact environment built during the Canonical AI Hackathon (May 2026). You'll end up with:

- A **Juju controller** on microk8s
- A **Wazuh 4.11.0 server stack** (manager, indexer, dashboard) via Docker Compose
- A **Wazuh agent** enrolled on the host, sending events to the dashboard
- A **Juju charm** (`wazuh-agent-operator`) ready to deploy

**Target host:** Ubuntu 24.04+ (tested on 26.04) with ≥4GB RAM, ≥2 CPUs, ≥20GB disk.
**AI model used:** DeepSeek V4 Pro via OpenClaw's sub-agent runtime.

---

## Table of Contents

1. [Host Preparation](#1-host-preparation)
2. [microk8s + Juju](#2-microk8s--juju)
3. [Wazuh Server via Docker](#3-wazuh-server-via-docker)
4. [Wazuh Agent on Host](#4-wazuh-agent-on-host)
5. [Building the Charm](#5-building-the-charm)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Host Preparation

```bash
# Update the system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo snap install yq        # YAML processor
sudo snap install charmcraft --channel latest/stable

# Verify versions
snap list | grep -E 'lxd|charmcraft'
```

---

## 2. microk8s + Juju

### 2.1 Install microk8s

> **⚠️ Critical:** Juju 3.6 **requires** strictly-confined microk8s. The `--classic` snap will NOT work.

```bash
# If classic microk8s is installed, remove it first
sudo snap remove microk8s --purge

# Install strictly confined microk8s
sudo snap install microk8s --channel 1.34-strict/stable

# Add your user to the snap_microk8s group (REQUIRED)
sudo usermod -a -G snap_microk8s $USER

# Apply group membership NOW (or log out/in)
newgrp snap_microk8s
# OR: sg snap_microk8s -c "bash"
```

### 2.2 Enable microk8s Addons

```bash
# From a shell with snap_microk8s group active:
sg snap_microk8s -c "microk8s status --wait-ready"

# Enable required addons
sg snap_microk8s -c "microk8s enable hostpath-storage"
sg snap_microk8s -c "microk8s enable dns"
sg snap_microk8s -c "microk8s enable metallb:10.197.95.200-10.197.95.210"

# Verify
sg snap_microk8s -c "microk8s status"
```

> **Note about MetalLB IP range:** Pick a range in your host's subnet that won't conflict with DHCP or existing hosts. Use `ip addr` to identify your network.

### 2.3 Install and Bootstrap Juju

```bash
sudo snap install juju --channel 3.6/stable

# Create storage directory Juju needs
sudo mkdir -p /var/lib/juju

# Bootstrap on microk8s
sg snap_microk8s -c "juju bootstrap microk8s microk8s-local"

# Verify
sg snap_microk8s -c "juju controllers"
sg snap_microk8s -c "juju status"
```

### 2.4 Create a Model

```bash
sg snap_microk8s -c "juju add-model wazuh-server"
```

---

## 3. Wazuh Server via Docker

Since running a full Juju-native Wazuh stack requires three controllers (K8s + LXD with cross-model relations), we use Docker Compose for the server — faster, simpler, and functionally equivalent for testing.

### 3.1 Install Docker & Docker Compose

```bash
# Docker
sudo apt install -y docker.io
sudo usermod -a -G docker $USER
newgrp docker

# Docker Compose V2
sudo apt install -y docker-compose-v2

# Verify
docker --version
docker compose version
```

### 3.2 Clone Wazuh Docker Repo

```bash
cd ~
git clone https://github.com/wazuh/wazuh-docker.git -b v4.11.0
cd wazuh-docker/single-node
```

### 3.3 Generate Indexer Certificates

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 3.4 Enable Password Enrollment (Critical)

Before starting the stack, the manager must accept enrollment with a password:

```bash
# The default config has use_password=no. Fix this:
# We'll patch it after the first start (see below)
```

### 3.5 Start the Stack

```bash
docker compose up -d

# Watch logs until everything is healthy (~2-3 min)
docker compose logs -f --tail 20
```

### 3.6 Configure Password Enrollment

```bash
# Edit the manager's ossec.conf to enable password auth
docker exec single-node-wazuh.manager-1 bash -c '
  sed -i "s|<use_password>no</use_password>|<use_password>yes</use_password>|" \
    /var/ossec/etc/ossec.conf
'

# Create enrollment password file
docker exec single-node-wazuh.manager-1 bash -c '
  echo "wazuh-enroll-password" > /var/ossec/etc/authd.pass
  chown wazuh:wazuh /var/ossec/etc/authd.pass
'

# Restart the manager
docker restart single-node-wazuh.manager-1
```

### 3.7 Verify the Stack

```bash
# Check containers are running
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check key ports are listening
ss -tlnp | grep -E '443|1514|1515|55000'

# Test manager API
docker exec single-node-wazuh.manager-1 \
  curl -sk -u wazuh-wui:MyS3cr37P450r.*- \
  https://localhost:55000/security/user/authenticate | head -1
```

### 3.8 Dashboard Access

| Field | Value |
|-------|-------|
| **URL** | `https://<host-ip>` |
| **Username** | `kibanaserver` |
| **Password** | `kibanaserver` |
| **Wazuh API user** | `wazuh-wui` |
| **Wazuh API password** | `MyS3cr37P450r.*-` |

> Accept the self-signed certificate warning — certificates are generated for `*.wazuh.internal` and won't match your host IP.

---

## 4. Wazuh Agent on Host

### 4.1 Install Matching Version

> **⚠️ Critical:** The agent version MUST be ≤ the manager version. Our manager is 4.11.0, so we install agent 4.11.0 exactly.

```bash
# Add Wazuh APT repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor \
  -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update

# Install a SPECIFIC version (not latest!)
sudo apt install -y wazuh-agent=4.11.0-1

# Pin the version so apt doesn't auto-upgrade
sudo apt-mark hold wazuh-agent
```

### 4.2 Configure the Agent

```bash
# Point agent to the manager (running on Docker, accessible via localhost)
sudo sed -i 's|<address>MANAGER_IP</address>|<address>127.0.0.1</address>|' \
  /var/ossec/etc/ossec.conf

# Create enrollment password file
echo "wazuh-enroll-password" | sudo tee /var/ossec/etc/authd.pass
sudo chown root:wazuh /var/ossec/etc/authd.pass
sudo chmod 640 /var/ossec/etc/authd.pass
```

### 4.3 Enroll and Verify

```bash
# Start the agent
sudo systemctl start wazuh-agent

# Check enrollment succeeded
sudo cat /var/ossec/etc/client.keys
# Should show: 001 dev-agent-vm any <key>

# Check agent logs
sudo tail -20 /var/ossec/logs/ossec.log

# Verify manager sees the agent
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
# Should show: ID: 001, Name: dev-agent-vm, IP: any, Active
```

### 4.4 Troubleshooting Enrollment

If the agent shows **Disconnected** after enrollment, it might need 10-30 seconds for the first keep-alive:

```bash
# Wait and re-check
sleep 30
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

# If still disconnected, check manager logs
docker exec single-node-wazuh.manager-1 tail -50 /var/ossec/logs/ossec.log | \
  grep -i "agent\|error\|invalid\|version"
```

Common enrollment failures:

| Symptom | Cause | Fix |
|---------|-------|-----|
| "version must be ≤ manager" | Agent newer than manager | Install exact match: `apt install wazuh-agent=4.11.0-1` |
| "Invalid password" | Password mismatch | Ensure `authd.pass` matches on both sides |
| dpkg conffile prompt | Old agent config not purged | `dpkg --purge --force-all wazuh-agent` before reinstall |
| `MANAGER_IP` in config | Env vars missing during install | Replace manually with `127.0.0.1` |

---

## 5. Building the Charm

### 5.1 The Charm Source

The full charm source is at `/home/ubuntu/.openclaw/workspace/wazuh-agent-operator/`:

```
wazuh-agent-operator/
├── charmcraft.yaml          # Build config (base: ubuntu@22.04)
├── metadata.yaml            # Charm metadata + relations
├── config.yaml              # 10 config options
├── actions.yaml             # 7 actions
├── src/
│   └── charm.py             # ~450 lines, ops framework
├── lib/charms/wazuh_agent/v0/
│   └── wazuh_server.py      # Relation data consumer library
├── tests/
│   ├── unit/test_charm.py   # 20+ unit tests
│   └── integration/test_charm.py
├── actions/                 # 7 action stubs
├── requirements.txt
├── pyproject.toml
├── tox.ini
├── README.md
└── LICENSE                  # Apache 2.0
```

### 5.2 Build (if LXD networking works)

```bash
cd wazuh-agent-operator
charmcraft pack
# Produces: wazuh-agent-operator_*.charm
```

> **Note:** charmcraft 4.x uses LXD managed builds. If LXD containers can't reach the internet, see [Troubleshooting](#6-troubleshooting) for the NAT fix.

### 5.3 Deploy and Relate

```bash
# Deploy the charm
juju deploy ./wazuh-agent-operator_*.charm wazuh-agent

# Or deploy with config
juju deploy ./wazuh-agent-operator_*.charm wazuh-agent \
  --config manager-address=10.197.95.152 \
  --config registration-password=wazuh-enroll-password

# When a wazuh-server charm exists, relate them
juju relate wazuh-agent wazuh-server

# Check status
juju status
```

---

## 6. Troubleshooting

### microk8s "Insufficient permissions"

```
$ microk8s status
Insufficient permissions to access MicroK8s
```

→ You're not in the `snap_microk8s` group:

```bash
sudo usermod -a -G snap_microk8s $USER
newgrp snap_microk8s
```

### Juju bootstrap fails on classic microk8s

```
ERROR juju.provider.kubernetes cannot bootstrap: ...
```

→ Remove classic microk8s and use strictly confined:

```bash
sudo snap remove microk8s --purge
sudo snap install microk8s --channel 1.34-strict/stable
```

### charmcraft managed build: "no network access"

The LXD bridge (`lxdbr0`) has no MASQUERADE rule for NAT:

```bash
# Check
sudo iptables -t nat -L POSTROUTING | grep 10.152

# Fix — add NAT rule for LXD subnet
sudo iptables -t nat -A POSTROUTING -s 10.152.16.0/24 ! -d 10.152.16.0/24 \
  -j MASQUERADE

# Make permanent
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-lxd.conf
sudo sysctl -p /etc/sysctl.d/99-lxd.conf
```

### Docker Compose: "port already in use"

```bash
# Check what's using the port
sudo ss -tlnp | grep <port>

# Stop the conflicting service or change the compose port mapping
```

### Wazuh agent version mismatch

The manager rejects agents with a higher version:

```
ERROR: Agent version must be lower or equal to manager version
```

→ Always install the **exact** matching agent version:

```bash
sudo apt install -y wazuh-agent=<manager-version>-1
sudo apt-mark hold wazuh-agent
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `/var/ossec/etc/ossec.conf` | Agent configuration (XML) |
| `/var/ossec/etc/client.keys` | Agent enrollment key (created on enrollment) |
| `/var/ossec/etc/authd.pass` | Enrollment password |
| `/var/ossec/logs/ossec.log` | Agent logs |
| `/var/ossec/bin/agent-auth` | Enrollment binary |
| `/var/ossec/bin/agent_control` | Agent status (manager side) |

---

## AI Acceleration Summary

This entire environment was built with **zero manual code** — a single prompt to OpenClaw:

> *"Generate a complete Juju charm for the Wazuh agent and set up a local test environment."*

| Task | Traditional | With AI |
|------|------------|---------|
| Charm code (450+ lines Python) | 4-5 hours | Minutes |
| Unit tests (20+ cases) | 2-3 hours | Minutes |
| Juju + microk8s setup | 1-2 hours | Minutes |
| Wazuh stack deployment | 1-2 hours | Minutes |
| Agent install + enrollment | 30 min | Minutes |
| Debugging (version, networking) | 1-2 hours | Minutes |
| Documentation + this tutorial | 2-3 hours | Minutes |
| **Total** | **~12+ hours** | **~2 hours** |

The AI handled every step: writing code, installing packages, debugging version mismatches, diagnosing snap confinement issues, fixing DPKG prompts, and configuring LXD networking. The human's role: reviewing output and providing the occasional "continue" or "fix that."

---

*Built with [OpenClaw](https://openclaw.ai) + [Juju](https://juju.is) + [Wazuh](https://wazuh.com) — May 2026*