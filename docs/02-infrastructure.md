# 02 - Hypervisor Infrastructure & Firewalling

## The Virtual Bridge (vmbr1)
The isolation layer was built using Proxmox VE. [cite_start]A dedicated Linux bridge (`vmbr1`) was created with the `bridge-ports none` directive[cite: 1012]. [cite_start]This ensures the bridge has no physical interface attached, creating a purely internal, virtual network (`10.0.20.0/24`) disconnected from the main router[cite: 938, 939].

## NAT Masquerading
To allow the honeypot VM to download necessary packages during installation without exposing its real origin, IP forwarding was enabled on the Proxmox host. [cite_start]A `POSTROUTING` rule with `MASQUERADE` allows the isolated subnet to reach the internet using the hypervisor's IP as a proxy[cite: 1000, 1013].

## Multi-Layer Hypervisor Firewall
[cite_start]To guarantee containment, strict `iptables` rules were applied directly at the hypervisor level[cite: 947, 954]. This prevents any lateral movement if the honeypot VM is compromised:

* [cite_start]**Protecting the Real LAN:** `iptables -I FORWARD -i vmbr1 -o vmbr0 -d 192.168.1.0/24 -j DROP` (Drops any traffic trying to reach the main home network)[cite: 865, 947, 1017].
* [cite_start]**Protecting the Hypervisor UI:** `iptables -I INPUT -i vmbr1 -p tcp --dport 8006 -j DROP` (Prevents access to the Proxmox web interface from the DMZ)[cite: 954, 1017].
* [cite_start]**Protecting the Hypervisor SSH:** `iptables -I INPUT -i vmbr1 -p tcp --dport 22 -j DROP` (Prevents access to the hypervisor's SSH from the DMZ)[cite: 954, 1017].