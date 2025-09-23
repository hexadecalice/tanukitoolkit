import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.tls.handshake import TLSClientHello


def process_packet(packet):
    #check if the packet has a DNS layer
    if packet.haslayer(DNS):
        #Check to ensure its a DNS Request
        if packet[DNS].qr == 0:
            #Check for actual DNS question, extra robustness to make sure packet isn't malformed
            if packet[DNS].qd:
                website_name = packet[DNSQR].qname.decode().lower()

                print("DNS PING: " + website_name)
    #Scanning for TCP packets to access the Server Name Index
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        #print("Packet has TCP layer and is on port 443")
        #Checking to ensure the TCP packet is doing an SSL handshake, so that the name can be accessed
        if packet.haslayer(TLSClientHello):
            #print("DEBUG: Packet has TLSClientHello message")
            #Finding the extension with servername
            for ext in packet[TLSClientHello].extensions:
                if hasattr(ext, "servername") and ext.servername:
                    print("Packet has servername attribute")
                    sni_name = ext.servername[0].host_name
                    sni_name = sni_name.decode('utf-8')
                    print("TCP PING: " + sni_name)
    return(None)

print("Scanning now...")
capture = scapy.sniff(prn=process_packet, store=False, filter="udp port 53 or tcp port 443")
