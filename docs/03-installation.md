# 03 - VM Provisioning & Cowrie Installation

## Virtual Machine Specifications
[cite_start]The honeypot runs on a minimal Debian 13 (netinst) virtual machine[cite: 997]. [cite_start]Resources were intentionally kept low (1 vCPU, 512MB RAM, 8GB Storage) as Cowrie primarily handles I/O logging operations and does not require heavy computational power[cite: 997, 1014].

## Cowrie Setup & Port Redirection
[cite_start]Cowrie was installed in a Python virtual environment and configured to listen internally on port `2222`[cite: 1001, 1015]. To make the honeypot believable and free up the standard SSH port, the following port manipulation was performed:

1. [cite_start]**Real SSH Relocation:** The actual SSH daemon of the VM was moved to port `22222` and secured with ED25519 key-based authentication[cite: 1016].
2. [cite_start]**Honeypot Interception:** A `PREROUTING` NAT rule was applied within the VM: `iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222`[cite: 1015]. Any attacker hitting port 22 is transparently redirected to the Cowrie sandbox.

## Systemd Persistence
[cite_start]To ensure the honeypot remains operational after reboots, a custom `cowrie.service` was created for `systemd`, allowing the Python application to run robustly in the background and start automatically on boot[cite: 1016].