# SSH Honeypot Architecture with Cowrie & Proxmox

## 🎯 Objective
To deploy an SSH honeypot (Cowrie) in a strictly isolated DMZ within Proxmox. This setup is exposed to the open internet to capture and analyze real-world intrusion attempts and threat intelligence, without compromising the underlying homelab infrastructure.

## 🏗️ Architecture & Network Flow

    Internet 
        │ 
        ▼ 
    Router (Port 22 → 192.168.1.100)
        │ 
        ▼ 
    Proxmox (vmbr0: 192.168.1.100, vmbr1: 10.0.20.1)
        │ 
        ▼ 
    VM Honeypot (10.0.20.10) ── Isolated DMZ
        │ 
        ✗ Blocked to Proxmox (Ports 8006, 22)
        ✗ Blocked to Real LAN (192.168.1.0/24)

## 📚 Project Documentation
The complete engineering process, from architectural decisions to threat intelligence analysis, is detailed in the `docs/` directory:

* [01 - Architecture & Design Principles](docs/01-architecture.md)
* [02 - Hypervisor Infrastructure & Firewalling](docs/02-infrastructure.md)
* [03 - VM Provisioning & Cowrie Installation](docs/03-installation.md)
* [04 - Threat Intelligence & Initial Findings](docs/04-threat-intelligence.md)

## 🛠️ Technology Stack
* **Hypervisor:** Proxmox VE
* **OS:** Debian 13 (Minimal)
* **Honeypot:** Cowrie
* **Networking & Security:** `iptables`, NAT Masquerading, Tailscale (Out-of-Band Management)

## 🚀 Key Features
* **True DMZ Isolation:** The honeypot resides on a virtual bridge (`vmbr1`) with no physical interface (`bridge-ports none`), ensuring default isolation.
* **Multi-Layer Firewalling:** Strict `iptables` drop rules at the hypervisor level prevent lateral movement to the LAN or management interfaces, even in the event of a sandbox escape.
* **Transparent Interception:** Real SSH is hidden on a non-standard port (`22222`), while an `iptables` `PREROUTING` rule transparently redirects attackers hitting port `22` into the Cowrie environment.
* **Actionable Intelligence:** Within 24 hours, the system successfully captured brute-force campaigns (e.g., 3000+ attempts from IP `45.156.87.253`), dictionary attacks, and targeted infrastructure probing for Web3/crypto nodes (`solana`, `validator`, `firedancer`) from IP `80.94.92.182`.