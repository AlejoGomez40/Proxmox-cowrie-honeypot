# 01 - Architecture & Design Principles

## The Honeypot Concept
The primary goal of this project is not to build a defensive wall, but to deploy an intelligence-gathering tool. By intentionally exposing a vulnerable-looking service (SSH on port 22) to the open internet, the system acts as a trap for automated botnets and targeted attacks. This allows for the collection of real-world threat intelligence, such as attacker IPs, brute-force dictionaries, and post-breach behavioral patterns.

## The Isolation Strategy (DMZ)
Deploying a honeypot on a primary network is a severe security risk. To mitigate this, the honeypot resides in a Demilitarized Zone (DMZ). This is implemented as a completely separated virtual network. If an attacker manages to exploit a zero-day vulnerability in the honeypot software and escapes the sandbox, they will find themselves trapped in an isolated subnet with no routing capabilities to the actual home lab network. 

## Out-of-Band Management (Tailscale)
A critical design decision was to avoid exposing any actual hypervisor administration ports (like Proxmox UI or real SSH) to the internet. Management access is handled strictly through a Tailscale mesh VPN installed directly on the hypervisor host. This ensures that while attackers can reach the honeypot, administrative interfaces remain completely invisible to the public internet.