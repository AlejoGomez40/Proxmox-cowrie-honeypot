# 04 - Threat Intelligence & Initial Findings

Within minutes of exposing port 22 to the internet, the honeypot began registering automated attacks. The logs (`/home/cowrie/cowrie/var/log/cowrie/cowrie.log`) revealed several distinct attack patterns.

## 1. Massive Brute-Force Campaigns
Certain IPs engaged in aggressive, sustained dictionary attacks. For example, the IP `45.156.87.253` executed over 3,000 login attempts in a single night.

## 2. Common Dictionary Testing
Many bots rely on default or highly predictable credentials. Frequent login attempts included:
* `support` / `support`
* `1234` / `1234`
* `root` / `password`

## 3. Targeted Infrastructure Probing
The most valuable intelligence gathered was identifying specialized bots hunting for specific infrastructure. The IP `80.94.92.182` specifically tested usernames related to Web3 and cryptocurrency nodes, including:
* `solana`
* `validator`
* `firedancer`
* `raydium`

This confirms that attackers are actively scanning the internet not just for generic servers, but specifically targeting homelabs and servers hosting valuable crypto assets.

*(Note: Screenshots of the raw logs can be found in the `screenshots/` directory).*