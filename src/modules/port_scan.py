import argparse
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import scapy.all as scapy
from scapy.all import IP, IPv6, TCP

from modules.host_gather import device_scan
from utils import utilities


common_ports = {
    20: 'FTP/Data',
    21: 'FTP/Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP/Server',
    68: 'DHCP/Client',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP'
}




def print_results(port, result):
    if result == "Open":
        print(f"Port {port} is open. (Common Usage: {common_ports.get(port, 'Unknown')})")
    elif result == "Closed":
        print(f"Port {port} is closed.")
    elif result == "Filtered":
        print(f"Port {port} is filtered.")
    elif result == "Status Unknown":
        print(f"Port {port}'s status is unknown. Please scroll up to find response packet information.")


def scan_port(ip, port, wait_time, ipv6_indicator, interface):
    sendSyn = None
    ip_layer = IPv6(dst=ip) if ipv6_indicator else IP(dst=ip)
    synReq = ip_layer / TCP(dport=port, flags="S")

    # I think the race condition is happening internally in Scapys threads from the traceback it gives
    # And if thats the case then idk how to fix that, this has never caught one error
    # But I'm leaving it here just in case ¯\_(ツ)_/¯
    try:
        sendSyn = scapy.sr1(synReq, verbose=0, timeout=wait_time)
    except PermissionError:
        utilities.print_error("Permission error thrown! Tanuki must be run with admin privileges (use sudo or 'run as administrator').")
        exit(-1)
    except OSError:
        utilities.print_error(f"Thread: {threading.current_thread().name} has failed, if this happens frequently, try reducing your max threads.")
        exit(-1)
        
    # Set conditionals for checking the response packet
    hasSynAck = sendSyn and sendSyn.haslayer('TCP') and sendSyn['TCP'].flags == 'SA'
    hasRst = sendSyn and sendSyn.haslayer('TCP') and (sendSyn['TCP'].flags == 'RA')
    hasAck = sendSyn and sendSyn.haslayer('TCP') and sendSyn['TCP'].flags == 'A'

    if hasSynAck:
        # Send RST tcp response with correct sequence and acknowledgement numbers to close the connection
        # We do this to end the connection while the TCP handshake is only half open, this makes it ~stealthier~
        rstPak = ip_layer / TCP(
            sport=synReq['TCP'].sport, 
            dport=port, 
            seq=sendSyn['TCP'].ack, 
            ack=sendSyn['TCP'].seq + 1, 
            flags="R"
        )
        
        utilities.safe_send(rstPak)
        return (port, "Open")
        
    elif hasRst:
        return (port, "Closed")
        
    elif not sendSyn or hasAck:
        return (port, "Filtered")
        
    else:
        sendSyn.show()
        return (port, "Status Unknown")


def main(host, ports, max_threads, wait_time, ipv6_indicator, interface):
    future_objects = []
    port_results = []
    
    # Scan common ports if no ports are provided
    if ports:
        port_list = ports
    else:
        port_list = common_ports

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for port in port_list: 
                result = executor.submit(scan_port, host, port, wait_time, ipv6_indicator, interface)
                future_objects.append(result)

            future_objects = as_completed(future_objects)
            for future in future_objects: 
                port_results.append(future.result())
                
            port_results.sort()

    except OSError:
        utilities.print_error("OSError occured, most likely an IP/website typo.\nPlease check your target IP and try again.")
        exit(1)
        
    for port, result in port_results:
        print_results(port, result)