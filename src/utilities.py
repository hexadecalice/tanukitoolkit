import socket
import ipaddress
import netifaces
from scapy.all import sr1, Ether, ARP, IP

welcome_message = "Tanuki Toolkit - ALPHA\nUse python tanuki.py -h for a list of commands."


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

def get_subnetmask(active_ip):
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for link in addresses[netifaces.AF_INET]:
                if link.get('addr') == active_ip:
                    if 'netmask' in link:
                        return link['netmask']
    return None



#Convert the determined IP/Subnet into a useable interface object that represents the network range
def format_range(host_ip, host_subnet):
    network_interface = ipaddress.IPv4Interface(f"{host_ip}/{host_subnet}")
    return network_interface


def find_router(router_ip):
    ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ether_layer/ARP(op=1, pdst=router_ip)
    response = sr1(arp_request)
    return response.hwsrc

def format_ports(port_input):

    format_error = "Please ensure your port is formatted single (ex. 8) or ranged (ex. 10,20)."
    invalid_port = "Invalid port numbers. Please try again."
    if ',' in port_input:
        ports = port_input.split(',')
        if len(ports) != 2:
            print(format_error)
            return None
        else:
            try:
                ports = list(map(int, ports))
            except ValueError:
                print(format_error)
                return None
            low, high = min(ports[0], ports[1]), max(ports[0], ports[1])
            if low < 0 or high > 65535:
                print(invalid_port)
                return None
            port_list = range(low, high+1)
            return port_list
    else:
        try:
            single_port = int(port_input)
            if not (0 <= single_port <= 65535):
                print(invalid_port)
                return None
        except ValueError:
            print(invalid_port)
            return None
        return [single_port]
