from scapy.all import IP, TCP
import scapy.all as scapy
import re
import asyncio
import concurrent.futures
import argparse
from host_gather import device_scan

#Change testip to the ip you want to scan the ports of
#Pro-tip: You can use host_gather.py to find IP's on your network to run this tool on

common_ports = {
     20: 'FTP/Data',
     21: 'FTP/Control',
     22: 'SSH',
     23: 'Telnet',
     25: 'SMTP',
     53: 'DNS',
     67: 'DHCP/Server',
     68: 'DHCP/Client',
     80: 'HTTP',
     110: 'POP3',
     123: 'NTP',
     143: 'IMAP',
     443: 'HTTPS',
     445: 'SMB',
     3306: 'MySQL',
     3389: 'RDP'
 }
error_message ="""Sorry! I didn't quite catch that, make sure your port is formatted start,end with no spaces!\n
Also ensure that the host is formatted properly as a www.website.com or IPv4 address!\n
Please restart the application."""

def printResults(port, result):
    if result == "Open":
        print("Port %s is open. (Common Usage: %s)" % (port, common_ports.get(port, "Unknown")))
    elif result == "Closed":
        print("Port %s is closed." % port)
    elif result == "Filtered":
        print("Port %s is filtered." % port)
    elif result == "Status Unknown":
        print("Port %s's status is unknown. Please scroll up to find response packet information." % port)


def scanPort(ip, port):
    synReq = IP(dst=ip)/TCP(dport=port, flags="S")
    sendSyn = scapy.sr1(synReq, verbose=0, timeout=2)
    #Set conditionals for checking the response packet
    hasSynAck = sendSyn and sendSyn.haslayer('TCP') and sendSyn['TCP'].flags == 'SA'
    hasRst = sendSyn and sendSyn.haslayer('TCP') and (sendSyn['TCP'].flags == 'RA')
    hasAck = sendSyn and sendSyn.haslayer('TCP') and sendSyn['TCP'].flags == 'A'

    if hasSynAck:
         #Send RST tcp response with correct sequence and acknowledgement numbers to close the connection
         #We do this to end the connection while the TCP handshake is only half open, this makes it ~stealthier~
        rstPak = IP(dst=ip)/TCP(sport=synReq['TCP'].sport, dport=port, seq=sendSyn['TCP'].ack, ack=sendSyn['TCP'].seq+1, flags="R")
        scapy.send(rstPak, verbose=0)
        return (port, "Open")
    elif hasRst:
             return (port, "Closed")
    elif not sendSyn or hasAck:
             return (port, "Filtered")
    else:
        sendSyn.show()
        return (port, "Status Unknown")



#This is a wrapper function, that takes our blocking scapy function
#And makes it asynchronous, using run_in_executor to tell asyncio that the entire function
#Is in and of itself, something thats blocking
async def async_scan_wrapper(exec,host,port):
    event_loop = asyncio.get_running_loop()
    port_result = await event_loop.run_in_executor(exec, scanPort, host, port)
    return port_result



async def main(host,ports,max_threads,):
    thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)

    if ports:
        #Regex to pull out the numbers from the flags input
        try:
            formatted_port = re.search(r"(\d+),(\d+)", ports)
            start_port = int(formatted_port.group(1))
            end_port = int(formatted_port.group(2))
            port_list = range(start_port, end_port+1)
        except:
            print(error_message)
            exit(1)

    #Scan common ports if no ports are provided
    else:
        port_list = common_ports
    #Create a list of tasks to be run 'asynchronously'
    #Then tell them to start running
    async_tasks = [async_scan_wrapper(thread_executor, host,port) for port in port_list]
    port_results = await asyncio.gather(*async_tasks)
    for port, result in port_results:
        printResults(port, result)






parser = argparse.ArgumentParser()
parser.add_argument("-ip",type=str, help="Specifies the host for target. Either a website or IP address.")
parser.add_argument("-p", type=str, help="Specifies the port range, written start,end")
parser.add_argument("-t",type=int, help="Sets the maximum number of threads. Default is 50.")
parser.add_argument("-lh", "--local_hosts", help="Prints the IP addresses/Mac addresses of local devices", action="store_true")

args = parser.parse_args()
#If local host flag is set, scan for local devices then exit the program
if args.local_hosts:
    local_host = device_scan(verbose=False)
    for host in local_host:
        print("IP Address: %s" % host.get("ip"))
        print("Mac Address: %s" % host.get("mac"))
        print("Manufacturer: %s" % host.get("manu"))
        print("Host Name (Usually undetermined): %s\n" % host.get("host name"))
    exit(1)
#Set arguments to variables to be used by the scanner
if args.ip == None:
    parser.print_help()
    exit(1)
else:
    target_host = args.ip

if args.t and args.t != 50:
    max_threads = args.t
else:
    max_threads = 50
asyncio.run(main(target_host,args.p,max_threads))
