# ARP-Watch
ARP-Watch is a software to prevent ARP Spoofing attacks on a network.
> **ARP Spoofing(/Poisoning)** - Maliciously crafted ARP packets can pretend to be another device in the network (by overriding the MAC address in the ARP cache).

> Thus, an attacker can cause a MITM (man-in-the-middle) attack where he intercepts outgoing packets from the victim.

ARP-Watch solves this problem by saving a trusted copy of the ARP cache in memory,
sniffs incoming ARP packets, to see for any change in the ARP cache and if there is, alert the user.

Moreover, if the program is running with the ``--heal`` flag, it will eventually discard any changes in the ARP cache.

## Usage
```
$ python arpwatch.py --help
usage: arpwatch.py [-h] [--heal]

Sniff ARP packets and watch for ARP spoofing

optional arguments:
  -h, --help  show this help message and exit
  --heal      In occasion of ARP spoofing, replace the poisoned entry from the
              ARP cache with the previous trusted entry.
```