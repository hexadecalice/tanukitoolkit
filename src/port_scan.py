from scapy.all import IP, TCP
import scapy.all as scapy
import re
import asyncio
import concurrent.futures
import argparse
import threading
from host_gather import device_scan

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
error_message ="""Sorry! I didn't quite understand.\nMake sure your port is formatted start,end with no spaces!\n
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


def scanPort(ip, port, wait_time):
    synReq = IP(dst=ip)/TCP(dport=port, flags="S")
    #I think the race condition is happening internally in Scapys threads from the traceback it gives
    #And if thats the case then idk how to fix that, this has never caught one error
    #But I'm leaving it here just in case ¯\_(ツ)_/¯
    try:
        sendSyn = scapy.sr1(synReq, verbose=0, timeout=wait_time)
    except OSError:
        print("Thread: " + threading.current_thread() + " has failed, if this happens frequently, try reducing your max threads.")
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
#And makes it asynchronous, using run_in_executor to assign it to a threadpool
#The threadpool handles the functions execution, and we tell asyncio that the threadpool task
#Is to be awaited
async def async_scan_wrapper(semaphore,exec,host,port,wait_time):
    async with semaphore:
        event_loop = asyncio.get_running_loop()
        port_result = await event_loop.run_in_executor(exec, scanPort, host, port, wait_time)
        return port_result



async def main(host,ports,max_threads,wait_time):
    thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
    thread_semaphore = asyncio.Semaphore(max_threads-(max_threads//2))
    if ports:
        #Regex to pull out the numbers from the flags input
        #There has to be a more graceful way to do this
        try:
            formatted_port = re.search(r"(\d+),(\d+)", ports)
            start_port = int(formatted_port.group(1))
            end_port = int(formatted_port.group(2))
            port_list = range(start_port, end_port+1)
        except(ValueError, AttributeError):
            print(error_message)
            exit(1)

    #Scan common ports if no ports are provided
    else:
        port_list = common_ports
    #Creates a list of tasks to be run 'asynchronously'
    #Then tell them to start running
    async_tasks = [async_scan_wrapper(thread_semaphore, thread_executor,host,port,wait_time) for port in port_list]
    try:
        port_results = await asyncio.gather(*async_tasks)
    except OSError:
        print("OSError occured, most likely an IP/website typo.\nPlease check your target IP and try again.")
        exit(1)
    for port, result in port_results:
        printResults(port, result)
