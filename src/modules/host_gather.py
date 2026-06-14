import scapy.all as scapy
import socket
import ipaddress
import netifaces

from utils import utilities

def device_scan(router_ip, mac_lookup, verbose=True, arp_poison=False):
    local_host = utilities.get_ip()
    local_subnetmask = utilities.get_subnetmask(local_host)
    cidr_prefix = utilities.format_range(local_host, local_subnetmask)
    print("\nScanning on network segment: " + str(cidr_prefix) + "...")
    print("This may take a while")


    #Create an ARP request with a broadcast ethernet envelope
    arp_request = scapy.ARP(pdst=str(cidr_prefix))
    ether_envelope = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #Layer the packets into something that can be sent on the network
    request_packet = ether_envelope / arp_request

    answered, unanswered = scapy.srp(request_packet, timeout=2, verbose=False)

    response_list = []

    for sent, received in answered:
        if received.psrc == router_ip:
            if verbose:
                print("--This Device Is The Router--")
            if arp_poison:
                return received.hwsrc
        if verbose:
            print("IP Address: %s" % received.psrc)
            print("Mac Address: %s " % received.hwsrc)
        #Use mac-lookup to determine manufacturer
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
