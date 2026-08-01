import ipaddress
import socket

import netifaces
import scapy.all as scapy

from utils import utilities


def device_scan(router_ip, mac_lookup, interface, verbose=True, arp_poison=False):
    # Uses the interface to find the ip and subnet mask if specified 
    # If not, use the hacky functions 
    if interface is None: 
        local_host = utilities.get_ip()
        local_subnetmask = utilities.get_subnetmask(local_host)
    else: 
        interface_info = utilities.get_interface_info(interface)
        local_host, local_subnetmask = interface_info[0], interface_info[1]

    cidr_prefix = utilities.format_range(local_host, local_subnetmask)
    utilities.print_info(f"Scanning on network segment: {cidr_prefix}...")
    utilities.print_info("This may take a while")

    # Create an ARP request with a broadcast ethernet envelope
    arp_request = scapy.ARP(pdst=str(cidr_prefix))
    ether_envelope = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Layer the packets into something that can be sent on the network
    request_packet = ether_envelope / arp_request

    answered, unanswered = scapy.srp(request_packet, timeout=2, verbose=False, iface=interface)

    response_list = []

    for sent, received in answered:
        if received.psrc == router_ip:
            if verbose:
                print("--This Device Is The Router--")
            if arp_poison:
                return received.hwsrc
                
        if verbose:
            print(f"IP Address: {received.psrc}")
            print(f"Mac Address: {received.hwsrc}")
            
        # Use mac-lookup to determine manufacturer
        try:
            manu_result = mac_lookup.lookup(received.hwsrc)
        except:
            manu_result = "Couldn't determine manufacturer"
            
        # Try to resolve host name from DNS server
        try:
            host_name = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            host_name = "Undetermined."
            
        if verbose:
            print(f"MAC Lookup Result: {manu_result}")
            print(f"Host name: {host_name}\n")
            
        response_info = {
            'ip': received.psrc, 
            'mac': received.hwsrc, 
            'manufacturer': manu_result, 
            'host name': host_name
        }
        response_list.append(response_info)
        
    return response_list