import subprocess
import ARP_Spoofing
import os
import Network_Discovery

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
        ARP_Spoofing.send_gratuitous_arp(target, Network_Discovery.get_mac_by_ip_SELF(IP), "255.255.255.0")
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
        return changeIPAddressWindows(interface, IP, Subnet)
    else:
        return changeIPAddressLinux(interface, IP, Subnet)