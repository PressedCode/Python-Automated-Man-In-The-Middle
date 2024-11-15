import scapy.all as scapy
import socket
import re
import subprocess
import psutil
import struct
import os

#Saves traffic to a pcap file, takes file name and interface as arguments
def NetCap(dest, interface):
    while 1:
        scapy.wrpcap(dest, scapy.sniff(iface=interface, count=10), append=True)

#Gets the IP for the device
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1)) # makes a socket connection to an IP address, doesnt matter if connection goes through just logs IP address from sender
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

#Gets Interface by checking all interfaces on a device and matching it to an IP address
def get_interface_from_ip(ip_address):
    # Get all network interfaces
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Check for the address family (IPv4)
            if addr.family == socket.AF_INET:
                # If the IP address matches, return the interface
                if addr.address == ip_address:
                    return interface
    return None

def get_mac_by_ip_windows(ip_address):
    try:
        # Run ipconfig /all and capture the output
        result = subprocess.run(['ipconfig', '/all'], stdout=subprocess.PIPE, text=True)
        output = result.stdout

        # Find the section that contains the IP address
        ip_section = None
        for section in re.split(r'\r?\n\r?\n', output):
            if ip_address in section:
                ip_section = section
                break

        if ip_section:
            # Find the MAC address in the same section
            mac_match = re.search(r'Physical Address[ .]*: ([\w-]+)', ip_section)
            if mac_match:
                return mac_match.group(1).replace("-", ":").lower()

        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_mac_by_ip_linux(ip_address):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Get the interface associated with the given IP address
        iface = None
        for i in range(10):  # Check up to 10 interfaces
            iface_name = f'eth{i}'
            try:
                iface_ip = socket.inet_ntoa(
                    struct.pack('256s', bytes(iface_name[:15], 'utf-8'))
                )
                if iface_ip == ip_address:
                    iface = iface_name
                    break
            except OSError:
                continue

        if not iface:
            return None

        # Use ioctl to get the MAC address
        mac_addr = struct.pack(
            '256s', bytes(iface[:15], 'utf-8')
        )[18:24]

        # Format MAC address
        mac_address = ':'.join('%02x' % b for b in mac_addr)
        return mac_address
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_mac_by_ip_SELF(ip_address):
    if (os.name == 'nt'):
        return get_mac_by_ip_windows(ip_address)
    else:
        return NetFunctions.get_mac_by_ip_linux(ip_address)

def get_mac_by_ip(target_address, ip_address):
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    # Create an ARP request
    arp = scapy.ARP(pdst=target_address)

    # Combine the Ethernet and ARP packet
    packet = ether / arp

    # Send the packet and capture the response
    try:
        # srp sends and receives packets at layer 2
        result = scapy.srp(packet, timeout=2, verbose=False, iface=get_interface_from_ip(ip_address))[0]
        # Parse the response to find the MAC address
        for sent, received in result:
            return received.hwsrc  # Return the MAC address

    except Exception as e:
        print(f"Error: {e}")

    return None
    
    return None  # Return None if no MAC address found

def packet_callback(packet):
    arr = [2]
    # Check if the packet has an Ethernet layer (Layer 2)
    try:
        dst_mac = packet[scapy.Ether].dst  # Destination MAC address
        arr[0] = dst_mac
    except:
        arr[0] = "ff:ff:ff:ff:ff:ff"

    # Check if the packet has an IP layer (Layer 3)
    try:
        dst_ip = packet[scapy.IP].dst  # Destination IP address
        arr[1] = dst_ip
    except:
        arr[1] = None

    return arr