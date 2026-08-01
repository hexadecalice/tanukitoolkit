from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, send, sniff
import socket
import time
from utils import utilities
from utils import config
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
        if packet.haslayer(DNS) and packet["DNS"].ancount > 0 and packet.haslayer(IP): 
            packet_ip = packet['IP'].src
            if packet_ip not in self.cache:
                utilities.print_info(f"Device detected at {packet_ip}")
                self.cache[packet_ip] = []
                answer = packet['DNS'].an 
                while answer: 
                    dns_record = { 
                        "name" : getattr(answer, "rrname", "Name not present"),
                        "record_type" : getattr(answer,"type", "Type not present"),
                        "additional_data" : getattr(answer, "rdata", "No additional data")
                    }
                    if dns_record not in self.cache: 
                        self.cache[packet_ip].append(dns_record)
                    answer = answer.payload if isinstance(answer.payload, 'DNSR') else None 
            

    def iterate_services(self, service_list): 
        for service in service_list: 
            multicast_ping = mDNS_wrapper/DNS(qr=0, qd=DNSQR(qname=service, qtype="PTR"))
            send(multicast_ping, verbose=False)

    def check_deep_probe(): 
        return 0


mDNS_wrapper = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)

def probe_mdns(scanner_object):
    send_thread = threading.Thread(target=scanner_object.iterate_services, args=(common_services,), daemon=True)
    sniff_thread = threading.Thread(target=lambda: sniff(prn=scanner_object.check_service, timeout=config.MDNS_TIMEOUT), daemon=True)

    utilities.print_info(f"Starting mDNS scan, please wait {config.MDNS_TIMEOUT} seconds to complete the scan.")
    utilities.print_info("If receiving fewer results than expected, increase the timeout in config.py by adjusting the MDNS_TIMEOUT variable.")

    sniff_thread.start()
    time.sleep(1)
    send_thread.start()

    sniff_thread.join()
    send_thread.join()
    
    clean_cache= [] 

    for device in scanner_object.cache: 
        print(device)
        
    


def deep_probe(device):
    query_types = ["A", "AAAA", "TXT", "SRV"]
    ip_layer = IP(dst=host['ip'])
    udp_layer = UDP(dport=5353)
    for type in query_types: 
        request = ip_layer/udp_layer/DNS(qr=0, qd=DNSQR(qname=host['service_name'], qtype=type))
        answer = sr1(request, timeout=2, verbose=False)
        if answer != None: 
            answer.show()


my_scanner = mDNS_Scanner()

first_probe = probe_mdns(my_scanner)
"""
print('\n')
utilities.print_info("Scan Summary:")
for device in first_probe:
    for record in device: 
        print(f"IP: {record["ip"]}")
        print(f"Service Name: {record["service_name"]}")
        print(f"Record Type: {record["record_type"]}")
        print(f"Additional Data: {record["record_additional_data"]}\n")


#deep_probe(first_probe)

"""