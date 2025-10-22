import argparse
import port_scan
import host_gather
import arp_spoof
import scanner
import netifaces
from getmac import get_mac_address as gma
import asyncio
welcome_message = "Tanuki Toolkit - ALPHA\nUse python tanuki.py -h for a list of commands."
print(welcome_message)
gateway = netifaces.gateways()
router_ip = gateway['default'][netifaces.AF_INET][0]
my_mac = gma()


#Setting the arguments for argparse
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--target-ip",type=str, help="Specifies the host for target. Either a website or IP address.")
parser.add_argument("-pr", "--port_range", type=str, help="Specifies a port range, formatted start,end. The default is a list of commonly used ports.")
parser.add_argument("-t", "--thread_maximum",type=int, help="Sets the maximum number of threads for port scanning. Default is 50.")
parser.add_argument("-tm", "--target_mac", help="Specifies target Mac Adddress for ARP poisoning")
parser.add_argument("-w", "--wait", type=float, help="Specifies the time a thread should wait for a port to respond in seconds. Default is 3.")
parser.add_argument("-lh", "--local_hosts", help="Prints the IP addresses/Mac addresses of local devices", action="store_true")
parser.add_argument("-ps", "--port_scan", help="Signifies that you would like to use the port scanning function of the toolkit, please include target IP.", action="store_true")
parser.add_argument("-arp", "--arp_poison", help="Starts an ARP MitM attack against a given target, please include IP and Mac of target", action="store_true")
parser.add_argument("-rm", "--router_mac", type=str, help="Used for specificing the router's mac address.")


args = parser.parse_args()
#Run host_gather and print the results to the screen if this flag is selected
if args.local_hosts:

    local_host = host_gather.device_scan(router_ip,verbose=False)
    for host in local_host:
        print("IP Address: %s" % host.get("ip"))
        print("Mac Address: %s" % host.get("mac"))
        print("Manufacturer: %s" % host.get("manufacturer"))
        print("Host Name (Usually undetermined): %s\n" % host.get("host name"))
    exit(1)
#Set arguments to variables to be used by the scanner
if args.target_ip == None:
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
    asyncio.run(port_scan.main(target_host,args.port_range,max_threads,wait_time))
    exit(1)


#Logic for handling the ARP poisoning program
if args.arp_poison:
    if args.target_mac:
        target_mac = args.target_mac
    else:
        print("Please enter a target mac using -tm for ARP spoofing.")
        print("For a full list of commands, use python tanuki.py -h")

    if args.router_mac:
        router_mac = args.router_mac
    else:
        router_mac = host_gather.device_scan(router_ip,verbose=False, arp_poison=True)
    if router_mac and isinstance(router_mac, str):
        try:
            #Pass our command line variables to arp_spoof and let it do its thing
            print("Beginning ARP Poison to host " + target_host + " and router at " + router_ip)
            arp_spoof.start_arp_poison(target_host, target_mac, router_ip, my_mac, router_mac)
        except TypeError:
            print("Something went wrong, make sure you're formatting the MAC correctly")
    else:
        print("Unable to determine router's mac, try entering it manually.")
