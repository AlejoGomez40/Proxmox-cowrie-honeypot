# 03 - VM Provisioning & Cowrie Installation

## Virtual Machine Specifications
The honeypot runs on a minimal Debian 13 (netinst) virtual machine. Resources were intentionally kept low (1 vCPU, 512MB RAM, 8GB Storage) as Cowrie primarily handles I/O logging operations and does not require heavy computational power.

## Cowrie Setup & Port Redirection
Cowrie was installed in a Python virtual environment and configured to listen internally on port `2222`. To make the honeypot believable and free up the standard SSH port, the following port manipulation was performed:

1. **Real SSH Relocation:** The actual SSH daemon of the VM was moved to port `22222` and secured with ED25519 key-based authentication.
2. **Honeypot Interception:** A `PREROUTING` NAT rule was applied within the VM: `iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222`. Any attacker hitting port 22 is transparently redirected to the Cowrie sandbox.

## Systemd Persistence
To ensure the honeypot remains operational after reboots, a custom `cowrie.service` was created for `systemd`, allowing the Python application to run robustly in the background and start automatically on boot.