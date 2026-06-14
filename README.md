# Project 01 — SSH Honeypot with Cowrie on Proxmox

> **Portfolio Project** · Cybersecurity & Networking  
> Part of a 10-project series built to prepare for roles in Big Tech.

---

## What this is

A production-grade SSH honeypot deployed on a home Proxmox server, isolated in a dedicated DMZ network segment, exposed to the real internet, and capturing live attack data from automated bots and human attackers.

This is not a simulation. Within hours of going live, real attackers connected and ran reconnaissance scripts against the honeypot. This repo documents the full process: architecture decisions, infrastructure setup, Cowrie configuration, and analysis of captured attacks.

---

## Why I built this

The goal was to understand how attackers think — not from a textbook, but from observing real behavior in a controlled environment.

A honeypot is a system designed to be attacked. It contains nothing of value, but it logs everything: IPs, credentials attempted, and every command executed after a successful (simulated) login. This is threat intelligence at its most direct.

SSH on port 22 is one of the most scanned services on the internet. Botnets constantly sweep the IPv4 space looking for weak credentials. By exposing a realistic-looking SSH server and capturing what attackers do once they "get in", you gain insight into real attack patterns — in this case, automated scripts fingerprinting the system to determine whether it's worth using as a cryptomining node.

---

## Architecture

The most important design decision was **network isolation**. Deploying a honeypot inside a real home network is reckless. Instead, the honeypot lives in a dedicated DMZ (demilitarized zone), completely isolated from the production LAN.

```
INTERNET
    │
    ▼
[Home Router]
    │
    ├── vmbr0 — LAN (192.168.1.0/24) ──── Proxmox UI, real VMs, personal machines
    │
    └── vmbr1 — DMZ (10.0.20.0/24) ───── VM: honeypot-cowrie (10.0.20.10)
                [NO physical NIC]          Port 22 forwarded from router
                                           Cannot initiate traffic to LAN
```

**Key isolation rules (enforced via iptables on Proxmox host):**
- DMZ → LAN traffic: `DROP`
- DMZ → Proxmox management (port 8006, 22): `DROP`
- Internet → honeypot port 22: `ALLOW` (via router port forward)

The DMZ bridge (`vmbr1`) has no physical NIC assigned. The honeypot cannot reach the internet on its own — it only receives inbound connections forwarded by the router.

---

## Why a VM, not a container

Proxmox supports both LXC containers and full VMs. For a system exposed to the internet, a VM is the correct choice: it has its own isolated kernel, whereas an LXC container shares the host kernel. A container escape vulnerability would directly compromise the Proxmox host. A VM escape is orders of magnitude harder.

---

## VM Specifications

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| OS | Debian 12 minimal | Small footprint, stable, well-documented with Cowrie |
| vCPU | 1 | Cowrie is I/O-bound, not CPU-bound |
| RAM | 512 MB | Logs are text — no heavy compute needed |
| Disk | 8 GB | Logs accumulate slowly |
| Network | vmbr1 only | Isolated to DMZ — no LAN access |
| VM ID | 200 | Convention: 200+ for service/DMZ VMs |

---

## Cowrie Setup

[Cowrie](https://github.com/cowrie/cowrie) is a medium-interaction SSH/Telnet honeypot written in Python. It simulates a full Linux shell: attackers can run commands, navigate a fake filesystem, and download files — while every action is logged.

### Key configuration choices

- **Hostname:** `svr01` — generic enough to not arouse suspicion
- **Listening ports:**
  - `tcp:2222:interface=0.0.0.0` — main honeypot port (mapped to 22 via iptables)
  - `tcp:2223:interface=0.0.0.0` — secondary port
  - `tcp:6415:interface=127.0.0.1` — internal management
- **Credentials:** configured to accept `debian/P455word` (and others) to allow attackers in
- **Run as:** dedicated `cowrie` user with no sudo privileges
- **Persistence:** managed via systemd (`cowrie.service`)

### Port forwarding chain

```
Internet:22 → Router → Proxmox host:22 → iptables DNAT → 10.0.20.10:2222
```

```bash
# On Proxmox host: forward incoming port 22 to the honeypot VM
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 22 -j DNAT --to-destination 10.0.20.10:2222
```

---

## Live Attack Data — 5 Days of Real Traffic

The honeypot ran from June 10–14, 2026, exposed to the real internet with no filtering. These are the raw numbers:

| Metric | Value |
|--------|-------|
| Total connections | 3,347 |
| Unique attacker IPs | 634 |
| Period | 5 days (Jun 10–14, 2026) |
| Average connections/day | ~669 |

---

### Top credentials attempted

These are the real username/password pairs attackers tried most frequently:

| Credential | Attempts |
|------------|----------|
| `support / support` | 37 |
| `1234 / 1234` | 24 |
| `admin / admin` | 9 |
| `ubuntu / ubuntu` | 8 |
| `node / node` | 7 |
| `master / qwerty` | 7 |
| `steam / steam` | 6 |
| `splunk / password` | 6 |
| `root / root` | 6 |
| `ftpuser / ftpuser123` | 6 |

The pattern is clear: these are dictionary attacks using default and common credentials, fully automated. No human is typing these — bots are cycling through wordlists at scale.

---

### Top commands executed

Once attackers got past authentication, the most executed commands were:

| Command | Count | Purpose |
|---------|-------|---------|
| `uname -s -v -n -r -m` | 2,596 | OS/kernel fingerprint |
| Full CPU/GPU recon script | 302 | Pre-mining resource check |
| `uname -m` | 302 | Architecture check |

The full recon script (executed 302 times) collects CPU model, core count, GPU via `lspci`, system uptime, and shell flavor. This is a **cryptomining pre-filter**: the botnet is deciding whether the machine is worth deploying a miner on before committing to a payload.

---

### Notable attack behaviors

**1. SSH backdoor persistence attempt**

One attacker attempted to install a permanent backdoor by injecting their own public key:

```bash
cd ~ && rm -rf .ssh && mkdir .ssh && \
echo "ssh-rsa AAAAB3NzaC1yc2E... mdrfckr" >> .ssh/authorized_keys && \
chmod -R go= ~/.ssh
```

This is a classic post-compromise persistence technique: delete existing authorized keys, create a clean `.ssh` directory, and inject their own key. The username embedded in the key (`mdrfckr`) is a known threat actor signature that appears in public threat intelligence feeds.

**2. Honeypot detection attempt**

One attacker tried to verify they were inside a honeypot before doing anything else:

```bash
systemctl status cowrie && ss -tlnp | grep 2222
```

This is sophisticated. They know Cowrie runs as a service named `cowrie` and listens on non-standard ports. The fact that this check exists means some attackers specifically scan for honeypots before proceeding — which is itself useful threat intelligence.

**3. Miner detection**

```bash
ps | grep '[Mm]iner'
ps -ef | grep '[Mm]iner'
```

Some attackers check whether a miner is already running before deploying their own — avoiding resource competition with other threat actors on the same machine.

---

---

### Attacker taxonomy — 3 distinct threat profiles

Analyzing the full dataset reveals three completely different attacker profiles, each with a different end goal:

---

**Profile 1 — Cryptomining bots** (`SSH-2.0-Go` client)

The most common profile. Uses a custom Go-based SSH client, connects, authenticates, and immediately runs a hardware fingerprinting script collecting CPU model, core count, GPU via `lspci`, and system uptime. Sessions last 1–2 seconds. If the machine doesn't meet resource thresholds, the bot disconnects and moves on. The botnet is pre-filtering targets before deploying a miner.

Representative IPs: `43.156.212.6`, `91.92.40.4`, `47.104.163.51`

---

**Profile 2 — Spam relay bots** (`SSH-2.0-OpenSSH_7.4` and `SSH-2.0-PuTTY_Release_0.84` clients)

These attackers don't execute shell commands at all. Instead, they authenticate and immediately attempt SSH port forwarding to external SMTP servers (ports 25 and 2525). The goal is to use the compromised machine as an anonymous mail relay to send spam. One session even captured the raw SMTP handshake:

```
EHLO test
```

The honeypot logged the full forwarding attempt including destination IPs (`77.88.21.158:25`, `62.210.131.144:2525`). Cowrie blocked the actual forwarding, but recorded everything.

Representative IPs: `191.36.154.175`, `118.26.153.102`, `124.239.169.52`, `119.200.229.33`, `213.209.159.56`

---

**Profile 3 — HTTPS tunneling bot** (`176.65.139.56`)

The most technically interesting session. After authenticating with `1234/1234`, this attacker attempted to tunnel HTTPS traffic through the honeypot toward `1.1.1.1:443`. Cowrie captured the full TLS ClientHello handshake in binary and generated a JA4 fingerprint (`t12i131000_f57a46bbacb6_ab7e3b40a677`), a modern TLS client identification technique used in threat intelligence.

This is SSH being used as an anonymization proxy, routing encrypted traffic through a compromised machine to hide the true origin.

---

| Profile | Client | Goal | Ports targeted |
|---------|--------|------|----------------|
| Cryptomining | `SSH-2.0-Go` | Hardware recon → deploy miner | SSH only |
| Spam relay | `SSH-2.0-OpenSSH_7.4` / PuTTY | Use host as SMTP relay | 25, 2525 |
| HTTPS tunneling | `SSH-2.0-Go` (variant) | Anonymous proxy for TLS traffic | 443 |

---

### Early captures (first 24 hours)

| IP | Behavior |
|----|----------|
| 45.156.87.253 | 3,000+ login attempts — dictionary brute-force |
| 80.94.92.182 | Searching for Solana/blockchain validator nodes |
| 87.251.64.176 | Repeated `support/support` |
| 176.65.139.56 | Repeated `1234/1234` + HTTPS tunneling attempt |

---

## Repo Structure

```
project-01-honeypot-cowrie/
├── README.md               ← This file
├── config/
│   ├── cowrie.cfg          ← Cowrie configuration (sanitized)
│   └── cowrie.service      ← systemd service unit
└── logs/
    └── attacks.log         ← Sample of real captured attack session
```

---

## Security Notes

- The `cowrie.cfg` in this repo is safe to share: all sensitive sections (Slack/Discord/Telegram webhooks, API keys) were never configured and remain as generic placeholders from the default template.
- The only customizations are `hostname` and `listen_endpoints`.
- The `attacks.log` contains only the attacker's commands against a fake system — no real system data is exposed.

---

## Skills demonstrated

- Network segmentation with VLANs and Linux bridges in Proxmox
- DMZ design and iptables firewall rules (NAT + FORWARD chain)
- Linux system hardening (dedicated unprivileged user, SSH key auth, systemd service management)
- Honeypot deployment and configuration (Cowrie)
- Real threat intelligence analysis from live attack data
- Infrastructure-as-documentation: understanding *why* each decision was made, not just how to execute it

---

*Part of a 10-project portfolio series · Summer 2025*
