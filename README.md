# SSH Honeypot Architecture with Cowrie & Proxmox

## 🎯 Objective
[cite_start]To deploy an SSH honeypot (Cowrie) in a strictly isolated DMZ within Proxmox[cite: 3, 31, 32]. [cite_start]This setup is exposed to the open internet to capture and analyze real-world intrusion attempts and threat intelligence, without compromising the underlying homelab infrastructure[cite: 13, 17, 33].

## 🏗️ Architecture & Network Flow

    Internet 
        │ 
        ▼ 
    Router (Port 22 → 192.168.1.100) [cite: 1010]
        │ 
        ▼ 
    Proxmox (vmbr0: 192.168.1.100, vmbr1: 10.0.20.1) [cite: 1010]
        │ 
        ▼ 
    VM Honeypot (10.0.20.10) ── Isolated DMZ [cite: 1010]
        │ 
        ✗ Blocked to Proxmox (Ports 8006, 22) [cite: 1010]
        ✗ Blocked to Real LAN (192.168.1.0/24) [cite: 1010]

## 📚 Project Documentation
The complete engineering process, from architectural decisions to threat intelligence analysis, is detailed in the `docs/` directory:

* [01 - Architecture & Design Principles](docs/01-architecture.md)
* [02 - Hypervisor Infrastructure & Firewalling](docs/02-infrastructure.md)
* [03 - VM Provisioning & Cowrie Installation](docs/03-installation.md)
* [04 - Threat Intelligence & Initial Findings](docs/04-threat-intelligence.md)

## 🛠️ Technology Stack
* [cite_start]**Hypervisor:** Proxmox VE [cite: 3]
* [cite_start]**OS:** Debian 13 (Minimal) [cite: 398]
* [cite_start]**Honeypot:** Cowrie [cite: 3]
* [cite_start]**Networking & Security:** `iptables`, NAT Masquerading, Tailscale (Out-of-Band Management) [cite: 93, 105, 458]

## 🚀 Key Features
* [cite_start]**True DMZ Isolation:** The honeypot resides on a virtual bridge (`vmbr1`) with no physical interface (`bridge-ports none`), ensuring default isolation[cite: 55, 1012].
* [cite_start]**Multi-Layer Firewalling:** Strict `iptables` drop rules at the hypervisor level prevent lateral movement to the LAN or management interfaces, even in the event of a sandbox escape[cite: 859, 954].
* [cite_start]**Transparent Interception:** Real SSH is hidden on a non-standard port (`22222`), while an `iptables` `PREROUTING` rule transparently redirects attackers hitting port `22` into the Cowrie environment[cite: 521, 528, 1015].
* [cite_start]**Actionable Intelligence:** Within 24 hours, the system successfully captured brute-force campaigns (e.g., 3000+ attempts from IP `45.156.87.253`), dictionary attacks, and targeted infrastructure probing for Web3/crypto nodes (`solana`, `validator`, `firedancer`) from IP `80.94.92.182`[cite: 837, 838, 842].