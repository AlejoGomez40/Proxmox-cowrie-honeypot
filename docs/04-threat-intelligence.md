# 04 - Threat Intelligence & Initial Findings

Within minutes of exposing port 22 to the internet, the honeypot began registering automated attacks. [cite_start]The logs (`/home/cowrie/cowrie/var/log/cowrie/cowrie.log`) revealed several distinct attack patterns[cite: 833, 836].

## 1. Massive Brute-Force Campaigns
Certain IPs engaged in aggressive, sustained dictionary attacks. [cite_start]For example, the IP `45.156.87.253` executed over 3,000 login attempts in a single night[cite: 842, 1017].

## 2. Common Dictionary Testing
Many bots rely on default or highly predictable credentials. [cite_start]Frequent login attempts included[cite: 834, 842]:
* `support` / `support`
* `1234` / `1234`
* `root` / `password`

## 3. Targeted Infrastructure Probing
The most valuable intelligence gathered was identifying specialized bots hunting for specific infrastructure. [cite_start]The IP `80.94.92.182` specifically tested usernames related to Web3 and cryptocurrency nodes, including[cite: 837, 838, 1017]:
* `solana`
* `validator`
* `firedancer`
* `raydium`

This confirms that attackers are actively scanning the internet not just for generic servers, but specifically targeting homelabs and servers hosting valuable crypto assets.

*(Note: Screenshots of the raw logs can be found in the `screenshots/` directory).*