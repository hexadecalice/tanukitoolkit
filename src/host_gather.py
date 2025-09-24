import scapy.all as scapy
import socket
import ipaddress
import netifaces
from mac_vendor_lookup import MacLookup


#Use netifaces to determine the default gateway
gateway = netifaces.gateways()
router_ip = gateway['default'][netifaces.AF_INET][0]

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # Get IP by parsing info from UDP socket thats created at useless port
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_subnetmask():
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for link in addresses[netifaces.AF_INET]:
                if 'netmask' in link:
                    return link['netmask']
    return None

#Convert the determined IP/Subnet into a useable interface object that represents the network range
def format_host(host_ip, host_subnet):
    network_interface = ipaddress.IPv4Interface(f"{host_ip}/{host_subnet}")
    return network_interface


def device_scan(verbose=True):
    local_host = get_ip()
    local_subnetmask = get_subnetmask()
    cidr_prefix = format_host(local_host, local_subnetmask)
    if verbose:
        print("Scanning on network segment: " + str(cidr_prefix) + "...\n")

    #Create an ARP request with a broadcast ethernet envelope
    arp_request = scapy.ARP(pdst=str(cidr_prefix))
    ether_envelope = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #Layer the packets into something that can be sent on the network
    request_packet = ether_envelope / arp_request

    answered, unanswered = scapy.srp(request_packet, timeout=10, verbose=False)

    response_list = []

    for sent, received in answered:
        if received.psrc == router_ip and verbose:
            print("--This Device Is The Router--")
        if verbose:
            print("IP Address: %s" % received.psrc)
            print("Mac Address: %s " % received.hwsrc)
        #Use mac-lookup to determine manufacturer
        mac_lookup = MacLookup()
        try:
            manu_result = mac_lookup.lookup(received.hwsrc)
        except:
            manu_result = "Couldn't determine manufacturer"
        #Try to resolve host name from DNS server
        try:
            host_name = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            host_name = "Undetermined."
        if verbose:
            print("MAC Lookup Result: %s " % manu_result)
            print("Host name: %s \n" % str(host_name))
        response_info = {'ip': received.psrc, 'mac': received.hwsrc, 'manufacturer': manu_result, 'host name': host_name}
        response_list.append(response_info)
    return response_list




scan_list = device_scan()
