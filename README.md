# 🍯 SSH Honeypot — Threat Intelligence Platform

> **Live Dashboard →** [alejogomez40.github.io/Proxmox-cowrie-honeypot/dashboard.html](https://alejogomez40.github.io/Proxmox-cowrie-honeypot/dashboard.html)

A production-grade SSH honeypot deployed on a home Proxmox server, isolated in a dedicated DMZ network segment, exposed to the real internet. Captures live attack data from automated botnets and human attackers — then analyzes it with a custom Python pipeline and interactive dashboard.

**This is not a simulation.** Within hours of going live, real attackers connected and ran reconnaissance scripts against the honeypot.

---

## 📊 Live Stats (4-day capture period)

| Metric | Value |
|--------|-------|
| Total events logged | 86,842 |
| Unique attacker IPs | 672 |
| SSH connections | 11,384 |
| Successful logins | 10,727 |
| Commands executed | 10,460 |
| Avg session duration | 4.85s |

---

## 🏗️ Architecture

```
Internet
    │
    ▼
[Router] ──── Port 22 forwarded
    │
    ▼
[Proxmox Host]
    │
    ├── vmbr0 (LAN: 192.168.1.x)
    │
    └── vmbr1 (DMZ: 10.0.20.x) ◄── isolated bridge, no LAN routing
              │
              └── [Honeypot VM] 10.0.20.10
                      │
                      └── Cowrie SSH (port 2222 → exposed as 22)
```

**Key isolation decisions:**
- DMZ bridge has no route to LAN — a compromised honeypot cannot pivot to home network
- Cowrie runs as unprivileged `cowrie` user inside a dedicated Debian VM
- All traffic is logged to structured JSON before any attacker interaction

---

## 🔍 Key Findings

### Attack infrastructure
The top attacker IPs (`45.153.34.x`, `91.92.40.x`, `91.92.42.x`) generated 750–800 connections each over 4 days, with nearly identical timing patterns — classic coordinated botnet behavior. The dominant SSH client fingerprint was `SSH-2.0-Go`, confirming automated tooling written in Go.

### Credential patterns
Most common successful credentials were `support:support`, `1234:1234`, and `admin:admin` — default credentials targeting IoT devices and routers rather than servers. Attackers try hundreds of credential pairs per session with sub-second delays, indicating automated spraying.

### Post-login behavior
After login, attackers consistently ran a multi-stage reconnaissance sequence:

**Stage 1 — System fingerprinting**
```bash
uname -s -v -n -r -m        # OS + kernel + architecture
cat /proc/cpuinfo            # CPU model (mining viability check)
cat /proc/uptime             # Uptime (stability check)
ifconfig / ip cloud print    # Network interfaces
```

**Stage 2 — Threat detection evasion**
```bash
ps | grep '[Mm]iner'         # Check for competing miners
ps -ef | grep '[Mm]iner'     # Alternative process scan
```

**Stage 3 — Backdoor installation**
```bash
cd ~; chattr -ia .ssh; lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh
```

**Stage 4 — Data exfiltration probing**
```bash
ls -la ~/.local/share/TelegramDesktop/tdata   # Telegram session theft
locate D877F783D5D3EF8Cs                       # Known malware hash lookup
```

This sequence matches the [Mirai](https://en.wikipedia.org/wiki/Mirai_(malware)) and crypto-miner botnet playbooks documented by threat intelligence firms.

---

## 🛠️ Stack

| Component | Technology |
|-----------|------------|
| Hypervisor | Proxmox VE 8 |
| Honeypot VM | Debian 13, Cowrie SSH |
| Network isolation | Proxmox DMZ bridge (vmbr1) |
| Log format | Structured JSON (JSONL) |
| Analysis | Python 3 (`analyze.py`) |
| Dashboard | Vanilla HTML + Chart.js |
| Hosting | GitHub Pages |

---

## 🚀 Reproduce This

### 1. Deploy Cowrie
```bash
# Create dedicated user
sudo adduser --disabled-password cowrie
su - cowrie

# Install Cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Start
bin/cowrie start
```

### 2. Run the analyzer
```bash
git clone https://github.com/AlejoGomez40/Proxmox-cowrie-honeypot
cd Proxmox-cowrie-honeypot

python3 analyze.py \
  --log-dir /home/cowrie/cowrie/var/log/cowrie \
  --output dashboard.html
```

### 3. View dashboard
Open `dashboard.html` in any browser — no dependencies, no server needed.

---

## ⚠️ Security Notes

- **Never expose a honeypot on the same network as production systems** — use a dedicated DMZ or VLAN
- The honeypot VM has no outbound internet access (firewall rules block egress) to prevent it being used as a bot
- Logs may contain malicious payloads — handle with care, never execute captured commands

---

## 📁 Repo Structure

```
├── analyze.py          # Log parser + dashboard generator
├── dashboard.html      # Interactive analytics dashboard (live data)
├── config/
│   ├── cowrie.cfg      # Cowrie configuration
│   └── cowrie.service  # systemd service file
└── logs/
    └── sample_attacks.json  # Sample log excerpt
```

---

*Built as part of a home lab security project. All data captured from real internet traffic.*
