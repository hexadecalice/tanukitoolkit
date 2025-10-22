import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.tls.handshake import TLSClientHello
from host_gather import get_ip

""" This serves primarily as a module for the ARP poison, right now its reading very limited traffic
Because DNS queries are easy to check. """

def process_packet(packet, ):
    #check if the packet has a DNS layer
    if packet.haslayer(DNS) and packet.haslayer(IP):
        #Check to ensure its a DNS Request
        if packet[DNS].qr == 0:
            #Check for actual DNS question, extra robustness to make sure packet isn't malformed
            if packet[DNS].qd:
                website_name = packet[DNSQR].qname.decode().lower()
                source_ip = packet[IP].src
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




    return(None)
