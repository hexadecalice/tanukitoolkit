from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, send, sniff
import socket
import time
from utils import utilities
import threading 
common_services = [
    "_http._tcp.local",     
    "_ssh._tcp.local",      
    "_ipp._tcp.local",      
    "_smb._tcp.local",
    "_airplay._tcp.local",  
    "_workstation._tcp.local", 
    "_printer._tcp.local",  
    "_telnet._tcp.local",   
    "_ftp._tcp.local",
    "_companion-link._tcp.local",
    "_googlecast._tcp.local"       
]


class mDNS_Scanner: 
    def __init__(self): 
        self.cache = {}
    def check_service(self, packet): 
        if packet.haslayer(DNS) and packet["DNS"].ancount > 0: 
            self.cache[packet['IP'].src] = packet['DNS'].an
    def iterate_services(self, service_list): 
        for service in service_list: 
            multicast_ping = mDNS_wrapper/DNS(qr=0, qd=DNSQR(qname=service, qtype="PTR"))
            send(multicast_ping)




mDNS_wrapper = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)

#easy_way = mDNS_Wrapper/DNS(qr=0, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype))







my_scanner = mDNS_Scanner()

send_thread = threading.Thread(target=my_scanner.iterate_services, args=(common_services,), daemon=True)
sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=my_scanner.check_service), daemon=True)

thread_list = [] 

thread_list.append(send_thread)
thread_list.append(sniff_thread)
for thread in thread_list: 
    thread.start()

for thread in thread_list:
    thread.join()
