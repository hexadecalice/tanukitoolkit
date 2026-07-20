from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, send
import socket
import time
from utils import utilities

common_services = [
    "_http._tcp.local",     
    "_ssh._tcp.local",      
    "_ipp._tcp.local",      
    "_smb._tcp.local",      
    "_airplay._tcp.local",  
    "_workstation._tcp.local", 
    "_printer._tcp.local",  
    "_telnet._tcp.local",   
    "_ftp._tcp.local"       
]


mDNS_wrapper = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)

easy_way = mDNS_Wrapper/DNS(qr=0, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype))


def check_for_response(packet): 
    if packet.haslayer(DNS) and packet["DNS"].ancount > 0): 
        dns_answer = packet[DNS].an





for service in common_services: 
    multicast_ping = mDNS_wrapper/DNS(qr=0, qd=DNSQR(qname=service, qtype="PTR"))
