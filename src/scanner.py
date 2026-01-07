from scapy.all import ARP, IP, TCP, DNS, DNSQR, sniff, Ether, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from host_gather import get_ip
from ipaddress import ip_address
import socket
""" This serves primarily as a module for the ARP poison, right now its reading very limited traffic
Because DNS queries are easy to check. """

def process_packet(packet):
    # Check for IPv4 or IPv6 with TCP
    if (packet.haslayer(IP) or packet.haslayer(IPv6)) and packet.haslayer(TCP):
        print("---PACKET INFO:---")
        layer = IP if packet.haslayer(IP) else IPv6
        print("Source IP: " + packet[layer].src)
        print("Destination IP: " + packet[layer].dst)
        #Check cache to see if IP has already been resolved,
        if packet[layer].dst in process_packet.cache:
            print("Hostname: " + process_packet.cache[packet[layer].dst])
        else:
            try:
                dns_lookup = socket.gethostbyaddr(packet[layer].dst)[0]
            except (socket.gaierror, socket.herror, IndexError):
                dns_lookup = "Not Found."
            process_packet.cache[packet[layer].dst] = dns_lookup
            print("Hostname: " +  dns_lookup)
        print("Source Port: " + str(packet[TCP].sport))
        print("Destination Port: " + str(packet[TCP].dport) + "\n")


    #check if the packet has a DNS layer
    if packet.haslayer(DNS) and (packet.haslayer(IP) or packet.haslayer(IPv6)):
        layer = IP if packet.haslayer(IP) else IPv6
        #Check to ensure its a DNS Request
        if packet[DNS].qr == 0:
            #Check for actual DNS question, extra robustness to make sure packet isn't malformed
            if packet[DNS].qd:
                website_name = packet[DNSQR].qname.decode().lower()
                source_ip = packet[layer].src
                print("DNS PING: " + website_name + "from source: " + source_ip)
    #Scanning for TCP packets to access the Server Name Index
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        #Checking to ensure the TCP packet is doing an SSL handshake, so that the name can be accessed
        if packet.haslayer(TLSClientHello):
            #Finding the extension with servername
            for ext in packet[TLSClientHello].extensions:
                if hasattr(ext, "servername") and ext.servername:
                    sni_name = ext.servername[0].host_name
                    sni_name = sni_name.decode('utf-8')
                    print("TCP PING: " + sni_name)
process_packet.cache = {}
