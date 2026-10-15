import argparse
import json
import time
from datetime import datetime
from pathlib import Path
import socket
import platform
import subprocess

import netifaces
from getmac import get_mac_address as gma
from mac_vendor_lookup import MacLookup

#This shuts up the "no cryptography" warning.
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.config import conf

from modules import arp_spoof
from modules import host_gather
from utils import config
from utils import utilities

AF_INET = netifaces.AF_INET
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEVICE_DATA_DIR = PROJECT_ROOT / "device_data"
DEVICE_DATA_DIR.mkdir(parents=True, exist_ok=True)


parser = argparse.ArgumentParser()
parser.add_argument(
    "-ip",
    "--target-ip",
    type=str,
    help="Specifies the host for target. Either a website or IP address.",
)
parser.add_argument(
    "-pr",
    "--port_range",
    type=str,
    help="Specifies a port range, formatted start,end. The default is a list of commonly used ports.",
)
parser.add_argument(
    "-t",
    "--thread_maximum",
    type=int,
    help="Sets the maximum number of threads for port scanning. Default is 50.",
)
parser.add_argument(
    "-tm",
    "--target_mac",
    help="Specifies target Mac Address for ARP poisoning"
)
parser.add_argument(
    "-w",
    "--wait",
    type=int,
    help="An integer specifying the time between packets being added to the send queue in ms.\nUse this for rate limiting.",
)
parser.add_argument(
    "-F",
    "--FAST",
    help="Removess rate limiting on the port scanner, this will cause odd results on some target.",
    action="store_true"
    )
parser.add_argument(
    "-lh",
    "--local_hosts",
    help="Prints the IP addresses/Mac addresses of local devices",
    action="store_true",
)
parser.add_argument(
    "-ps",
    "--port_scan",
    help="Signifies that you would like to use the port scanning function of the toolkit, please include target IP.",
    action="store_true",
)
parser.add_argument(
    "-arp",
    "--arp_poison",
    help="Starts an ARP MitM attack against a given target, please include IP and Mac of target, or use the -r flag.",
    action="store_true",
)
parser.add_argument(
    "-rm",
    "--router_mac",
    type=str,
    help="Used for specifying the router's mac address.",
)
parser.add_argument(
    "-dos",
    "--dos_target",
    help="Poisons ARP target with garbage mac address.",
    action="store_true",
)

# Soon to be implemented, just haven't gotten around to it yet
parser.add_argument(
    "-ipv6",
    "--ipv6_indicator",
    help="Instructs all modules called to utilize IPv6 protocols whenever possible.",
    action="store_true",
)
parser.add_argument(
    "-r",
    "--read_device_file",
    help="Instructs the ARP module to read from a previously discovered list of devices",
    action="store_true",
)
parser.add_argument(
    "-i",
    "--interface",
    type=str,
    default=None,
    help="Selects which interface to scan/spoof/etc"
)



args = parser.parse_args()


print(utilities.welcome_message)
print(utilities.version)


"""
-------------------------------------------------------------------------------
Determining gateway/interfaces
-------------------------------------------------------------------------------
Code for finding the router IP; precedence order:
config.py -> selected interface gateway -> default gateway
"""
gateways = netifaces.gateways()

if args.interface is None:
    try:
        # Checks the routing table first, then the config folder.
        if config.ROUTER_IP is None:
            gateway_tuple = gateways["default"][AF_INET]
            router_ip, args.interface = gateway_tuple[0], gateway_tuple[1]
        else:
            router_ip = config.ROUTER_IP
            if config.INTERFACE is None:
                utilities.print_error("Inteface not set for custom router IP.")
                utilities.print_error("Please set the interface by changing the INTERFACE variable found in config.py")
                exit(1)
            args.interface = config.INTERFACE
    except KeyError:
        utilities.print_error("Default Gateway couldn't be determined, try specifying an interface.")
        utilities.print_error("You can also manually set your gateway's IP by modifying the ROUTER_IP variable in src/utilities/config.py")
        exit(1)
else:
    router_ip = None
    ipv4_gateways = gateways.get(netifaces.AF_INET, [])
    for gateway_tuple in ipv4_gateways:
        if args.interface == gateway_tuple[1]:
            router_ip = gateway_tuple[0]

    if router_ip is None:
        if config.ROUTER_IP is not None:
            router_ip = config.ROUTER_IP
        else:
            utilities.print_warning("Couldn't determine the interfaces gateway!")
            utilities.print_warning("For simple scans, this won't affect usage, but ARP spoofing requires the gateway address.")
            utilities.print_warning("You can manually set the gateway by changing the ROUTER_IP variable in src/utilities/config.py")

my_mac = gma(interface=args.interface)
mac_lookup = MacLookup()
conf.iface = args.interface
device_data_filename = DEVICE_DATA_DIR / f"{config.DEVICE_FILE}-{args.interface}.json"



"""
-------------------------------------------------------------------------------
Local host discovery
-------------------------------------------------------------------------------
"""
if args.local_hosts:
    local_host = host_gather.device_scan(
        router_ip,
        mac_lookup,
        args.interface,
        verbose=False,
    )

    for host in local_host:
        print(f"IP Address: {host.get('ip')}")
        print(f"Mac Address: {host.get('mac')}")
        print(f"Manufacturer: {host.get('manufacturer')}")
        print(f"Host Name (Usually undetermined): {host.get('host name')}\n")

    scan_time = str(datetime.now())
    json_contents = {
        "interface": args.interface,
        "time": scan_time,
        "devices": local_host,
    }

    with open(device_data_filename, "w") as file:
        json.dump(json_contents, file)

    exit(0)


"""
-------------------------------------------------------------------------------
Handling threadcount
-------------------------------------------------------------------------------
"""
if args.target_ip is None and not args.read_device_file:
    utilities.print_error("No target specified. Use -ip to specify a target or -lh to discover hosts.")
    parser.print_help()
    exit(1)
else:
    target_host = args.target_ip

if args.thread_maximum and args.thread_maximum > 0:
    max_threads = args.thread_maximum
else:
    max_threads = config.DEFAULT_THREAD_MAX

if args.wait is not None and not args.FAST:
    if args.wait >= 0:
        wait_time = args.wait
    else: 
        utilities.print_error("Wait time specified is invalid, please check your -w flag and try again.")
        exit(1)
elif args.FAST: 
    wait_time = 0
else:
    wait_time = config.DEFAULT_PS_DELAY_MS


"""
-------------------------------------------------------------------------------
Port scanning module handlingD
-------------------------------------------------------------------------------
"""
if args.port_scan:
    if args.port_range:
        port_range = utilities.format_ports(args.port_range)
        if port_range is None:
            utilities.print_warning(
                "Invalid port range supplied. Defaulting to common ports."
            )

    else:
        port_range = None

        #Checks if the entered target has a number, kind of a weak way to check if its an IP but eh
        #Assigns host ip and hostname depending on whether they entered a website or not
    if(args.target_ip[0].isdigit()):
        scan_ip = args.target_ip
        try: 
            scan_host = socket.gethostbyaddr(args.target_ip)[0]
        except socket.herror:
            utilities.print_warning("Couldn't resolve a host name from target, if it's not a website this is expected.")
            scan_host = "Undetermined"
    else: 
        try: 
            scan_ip = socket.gethostbyname(args.target_ip)
            scan_host = args.target_ip
        except socket.gaierror:
            utilities.print_error("Couldn't resolve website name, check your spelling and try again!")
            exit(1)

    

    
    if port_range is None: 
        start_port = 1
        end_port = config.DEFAULT_PORT_MAX
    else: 
        start_port = port_range[0]
        end_port = port_range[-1]
    local_ip = utilities.get_ip(args.interface)

    current_os = platform.system()
    if current_os == "Windows":
        port_binary = Path(__file__).resolve().parent / "modules" / "binaries" / "port_scan.exe"
    elif current_os == "Linux":
        port_binary = Path(__file__).resolve().parent / "modules" / "binaries" / "port_scan"
    else: 
        print("Tanuki currently only supports Windows and Linux systems, sorry!")
        exit(1)
    try: 
        subprocess.run(
            [port_binary, 
            scan_host,
            str(start_port),
            str(end_port),
            args.interface,
            str(max_threads),
            str(config.DEFAULT_THREAD_MAX), 
            scan_ip, 
            local_ip,
            str(wait_time)
            ], check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Couldn't start port sniffing binary, failed with error {exc}")         


    exit(0)

if not args.dos_target:
    args.dos_target = False


"""
-------------------------------------------------------------------------------
ARP module handling
-------------------------------------------------------------------------------
"""
if args.arp_poison or args.read_device_file:
    # Sets router mac and determines it if not found.
    if args.router_mac:
        router_mac = args.router_mac
    elif (not args.router_mac) and (not args.read_device_file):
        utilities.print_info("Attempting to determine router MAC...")
        router_mac = utilities.find_router_mac(router_ip)
    else:
        router_mac = None

    target_host = None
    target_mac = None

    if args.read_device_file:
        try:
            with open(device_data_filename, "r") as file:
                saved_data = json.load(file)
        except FileNotFoundError:
            utilities.print_error(
                "Data file not found! Try running tanuki.py -lh first to populate the file."
            )
            exit(1)

        scan_time = saved_data.get("time")
        active_interface = saved_data.get("interface")
        device_list = saved_data.get("devices")

        utilities.print_info("Scan data loaded successfully.")
        utilities.print_info(f"Time of scan recorded as {scan_time}")
        utilities.print_info(f"Scan recorded on {active_interface}")
        utilities.print_info(
            "For best results, ensure your -lh scan was run recently."
        )

        # I hate format strings so goddamn much. A pain to write and to look at.
        for index, host in enumerate(device_list, start=1):
            if host.get('ip') == router_ip:
                router_mac = host.get('mac')

            print(
                f"[{index}] "
                f"IP: {host.get('ip'):<15} | "
                f"MAC: {host.get('mac')} | "
                f"Host: {host.get('host name')}"
            )

        if router_mac is None or router_ip is None:
            utilities.print_error(
                "Couldn't determine gateway details from device data file."
            )
            utilities.print_error(
                "Try specifying the router's mac using the -rm flag, "
                "and/or setting the ROUTER_IP variable in config.py"
            )
            exit(1)

        user_input = input(
            "Please enter the device you would like to scan:\n> "
        )

        # Conditional makes sure its in range and is a number
        if (
            user_input.isdigit()
            and 1 <= int(user_input) <= len(device_list)
        ):
            index = int(user_input) - 1
            target_host = device_list[index].get("ip")
            target_mac = device_list[index].get("mac")
        else:
            utilities.print_error(
                "Sorry! Invalid input, please try again."
            )
            exit(1)

    else:
        if args.target_mac:
            target_mac = args.target_mac
        else:
            utilities.print_error(
                "Please enter a target mac using -tm for ARP spoofing."
            )
            utilities.print_error(
                "Alternatively, use -lh to gather hosts and run the ARP command with the -r flag."
            )
            utilities.print_error(
                "For a full list of commands, use python tanuki.py -h"
            )
            exit(1)

        if args.target_ip:
            target_host = args.target_ip
        else:
            utilities.print_error(
                "Please enter a target ip with -ip for ARP Spoofing"
            )
            utilities.print_error(
                "Alternatively, use -lh to gather hosts and run the ARP command with the -r flag."
            )
            utilities.print_error(
                "For a full list of commands, use python tanuki.py -h"
            )
            exit(1)

    if router_mac and isinstance(router_mac, str):
        try:
            # Pass our command line variables to arp_spoof and let it do its thing
            utilities.print_info(
                f"Beginning ARP Poison to host "
                f"{target_host} and router at {router_ip}"
            )

            config.INTERFACE = args.interface

            thread_list = arp_spoof.start_arp_poison(
                target_host,
                target_mac,
                router_ip,
                my_mac,
                router_mac,
                args.dos_target,
            )

            while 1:
                time.sleep(2)

        except (TypeError, ValueError) as e:
            utilities.print_error(
                "Something went wrong, make sure you're formatting "
                "your arguments correctly."
            )
            print(e)

        except KeyboardInterrupt:
            utilities.print_info("Keyboard Interrupt detected.")
            utilities.print_info(
                "Closing threads and ending ARP Poison..."
            )

            arp_spoof.stop_event.set()

            for thread in thread_list:
                thread.join()

            utilities.print_info(
                "Restoring target's ARP tables..."
            )

            try:
                arp_spoof.restore_arp_tables(
                    target_host,
                    router_ip,
                    router_mac,
                    target_mac,
                )
            except KeyboardInterrupt:
                utilities.print_warning(
                    "Forcefully closing Tanuki, target's ARP tables "
                    "may remain poisoned!"
                )
                exit(1)

            utilities.print_info("Exiting...")

    else:
        utilities.print_error(
            "Unable to determine router's mac, try entering it manually."
        )