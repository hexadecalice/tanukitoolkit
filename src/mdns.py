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
            self.cache[packet['IP'].src] = packet['DNS'].an
    def iterate_services(self, service_list): 
        for service in service_list: 
            multicast_ping = mDNS_wrapper/DNS(qr=0, qd=DNSQR(qname=service, qtype="PTR"))
            send(multicast_ping, verbose=False)

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
    
    results = []
    for key in scanner_object.cache:
        record = scanner_object.cache[key]
        results.append({
            "ip": key,
            "service_name": record.rrname,
            "record_type": record.type,
            "record_additional_data": record.rdata
        })
        
    return results


def deep_probe(scan_results):
    query_types = ["A", "AAAA", "TXT", "SRV"]
    for host in scan_results: 
        ip_layer = IP(dst=host['ip'])
        udp_layer = UDP(dport=5353)
        for type in query_types: 
            request = ip_layer/udp_layer/DNS(qr=0, qd=DNSQR(qname=host['service_name'], qtype=type))
            answer = sr1(request, timeout=2)
            if answer != None: 
                answer.show()


my_scanner = mDNS_Scanner()

first_probe = probe_mdns(my_scanner)
deep_probe(first_probe)

