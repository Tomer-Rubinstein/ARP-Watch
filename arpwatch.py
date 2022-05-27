from scapy.all import *
import subprocess
import re
from datetime import datetime, date
import argparse

ARPCache = {}
conf.verb = 0

parser = argparse.ArgumentParser(description='Sniff ARP packets and watch for ARP spoofing')
parser.add_argument('--heal', action='store_true', help='In occasion of ARP spoofing, replace the poisoned entry from the ARP cache with the previous trusted entry.')
args = parser.parse_args()


"""
loadArpCache() loads the current ARP cache of the PC to the ARPCache hashmap.
@params: null
@return: null
"""
def loadArpCache():
  cmdOut = subprocess.run(["arp", "-a"], capture_output=True).stdout.decode("utf-8").split("\n")

  for i in range(len(cmdOut)):
    if "Interface" in cmdOut[i]:
      interface = cmdOut[i].replace("\r", "")
      ARPCache[interface] = {}
      j = i+2
      while cmdOut[j].strip() != "":
        line = cmdOut[j]

        currIPv4 = re.search(
          "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
          line
        ).group()

        currMac = re.search(
          "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})",
          line
        ).group()

        ARPCache[interface][currIPv4] = currMac
        j += 1


"""
handlePacket(packet) will provoke when an ARP packet was recieved.
It will then check for changes in the trusted ARP cache,
and if any, ARP spoofing attempt has occurred.
@params:
  - packet, an <scapy.layers.l2.Ether> object representing an ARP packet
@returns: null
"""
def handlePacket(packet):
  for interface in ARPCache:
    if packet.psrc in ARPCache[interface].keys() and ARPCache[interface][packet.psrc] != packet.hwsrc.replace(":", "-"):
      currDate = date.today().strftime("%D.%M.%Y")
      currTime = datetime.now().strftime("%H:%M:%S")
      print(f"[!] ARP poisoning detected at {interface}:\n")
      print(f"\tDate: {currDate} by {currTime}")
      print(f"\tSuspect's MAC address: {packet.hwsrc}")

      if args.heal: healArpCache(packet.psrc, ARPCache[interface][packet.psrc])


"""
healArpCache(ip, mac) replaces a given poisoned entry (corresponding to parameter ip)
with a trusted MAC address(mac) on the PC's ARP cache.
@params:
  - ip(string), IPv4 address (in order to find the entry).
  - mac(string, seperated by '-'),  the trusted MAC address
@returns: null
"""
def healArpCache(ip, mac):
  # delete the host corresponding to the given ip param
  print(subprocess.run(["arp", "-d", ip], capture_output=True).stdout.decode("utf-8"))
  # add a new static entry (key=ip, value=mac)
  print(subprocess.run(["arp", "-s", ip, mac], capture_output=True).stdout.decode("utf-8"))


"""
"""
def saveTrustedArpJSON(): pass


"""
"""
def loadTrustedArpJSON(): pass


if __name__ == "__main__":
  # load the current ARP cache to memory under the assumption that it's trusted.
  loadArpCache()
  # sniff for incoming ARP packets and provoke handlePacket() when one was received.
  sniff(filter="arp", store=False, prn=handlePacket)
