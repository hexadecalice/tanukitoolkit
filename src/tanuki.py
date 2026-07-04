import argparse
import time
import json
import netifaces
from datetime import datetime
from getmac import get_mac_address as gma
from mac_vendor_lookup import MacLookup

from modules import arp_spoof
from modules import host_gather
from modules import port_scan
from modules import scanner
from utils import config
from utils import utilities

welcome_message = (
    "Tanuki Toolkit - BETA\nUse python tanuki.py -h for a list of commands."
)
gateway = netifaces.gateways()
router_ip = gateway["default"][netifaces.AF_INET][0]
my_mac = gma()
mac_lookup = MacLookup()


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
    "-tm", "--target_mac", help="Specifies target Mac Adddress for ARP poisoning"
)
parser.add_argument(
    "-w",
    "--wait",
    type=float,
    help="Specifies the time a thread should wait for a port to respond in seconds. Default is 3.",
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
    help="Starts an ARP MitM attack against a given target, please include IP and Mac of target",
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

#Soon to be implemented, just haven't gotten around to it yet
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


args = parser.parse_args()
print(utilities.welcome_message)

#Run host_gather and print the results to the screen if this flag is selected
if args.local_hosts:
    mac_lookup = MacLookup()
    local_host = host_gather.device_scan(router_ip, mac_lookup, verbose=False)
    for host in local_host:
        print("IP Address: %s" % host.get("ip"))
        print("Mac Address: %s" % host.get("mac"))
        print("Manufacturer: %s" % host.get("manufacturer"))
        print("Host Name (Usually undetermined): %s\n" % host.get("host name"))
    time = str(datetime.now())
    json_contents = {"time":time, "devices":local_host}
    with open(config.DEVICE_FILE, "w") as file:
        json.dump(json_contents, file)

    exit(0)


if args.target_ip == None and not args.read_device_file:
    parser.print_help()
    exit(1)
else:
    target_host = args.target_ip

if args.thread_maximum and args.thread_maximum > 0:
    max_threads = args.thread_maximum
else:
    max_threads = 50
if args.wait:
    wait_time = args.wait
else:
    wait_time = 3

if args.port_scan:
    if args.port_range:
        port_range = utilities.format_ports(args.port_range)
    else:
        port_range = None
    port_scan.main(target_host, port_range, max_threads, wait_time, args.ipv6_indicator)
    exit(0)
if not args.dos_target:
    args.dos_target = False

#Logic for handling the ARP poisoning program
if args.arp_poison:

    #Sets router IP and determines it if not found.
    if args.router_mac:
        router_mac = args.router_mac
    else:
        print("Attempting to determine router MAC...")
        router_mac = host_gather.device_scan(
            router_ip, mac_lookup, verbose=False, arp_poison=True
        )

    target_host = None
    target_mac = None

    if args.read_device_file:
        try:
            with open(config.DEVICE_FILE, "r") as file:
                saved_data = json.load(file)
        except FileNotFoundError:
            print("Data file not found! Try running tanuki.py -lh first to populate the file.")
            exit(1)
        scan_time = saved_data.get("time")
        device_list = saved_data.get("devices")

        #I hate format strings so goddamn much. A pain to write and to look at.
        for index, host in enumerate(device_list, start=1):
            print(f"[{index}] IP: {host.get('ip'):<15} | MAC: {host.get('mac')} | Host: {host.get('host name')}")
        user_input = input("Please enter the device you would like to scan:\n> ")

        #Conditional makes sure its in range and is a number
        if user_input.isdigit() and 0 <= int(user_input) <= len(device_list):
            index = int(user_input) - 1
            target_host = device_list[index].get("ip")
            target_mac = device_list[index].get("mac")
        else:
            print("Sorry! Invalid input, please try again.")
            exit(1)
    else:
        #Determine target host and mac 
        if args.target_mac:
            target_mac = args.target_mac
        else:
            print("Please enter a target mac using -tm for ARP spoofing.")
            print("Alternatively, use -lh to gather hosts and run the ARP command with the -r flag.")
            print("For a full list of commands, use python tanuki.py -h")
        if args.target_ip:
            target_host = args.target_ip
        else:
            print("Please enter a target ip with -ip for ARP Spoofing")
            print("Alternatively, use -lh to gather hosts and run the ARP command with the -r flag.")
            print("For a full list of commands, use python tanuki.py -h")



    if router_mac and isinstance(router_mac, str):
        try:
            #Pass our command line variables to arp_spoof and let it do its thing
            print(
                "Beginning ARP Poison to host "
                + target_host
                + " and router at "
                + router_ip
            )
            thread_list = arp_spoof.start_arp_poison(
                target_host, target_mac, router_ip, my_mac, router_mac, args.dos_target
            )
            while 1:
                time.sleep(2)
        except (TypeError, ValueError):
            print("Something went wrong, make sure you're formatting your arguments correctly.")
        except KeyboardInterrupt:
            print("--Ctrl+C Detected--")
            print("Closing threads and ending ARP Poison...")
            arp_spoof.stop_event.set()

            for thread in thread_list: 
                thread.join()

            print("Restoring target's ARP tables...")
            arp_spoof.restore_arp_tables(target_host, router_ip, router_mac, target_mac)
            print("Exiting...")

    else:
        print("Unable to determine router's mac, try entering it manually.")
