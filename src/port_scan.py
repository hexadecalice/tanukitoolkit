from scapy.all import IP, TCP
import scapy.all as scapy
import re
import asyncio
import time
import concurrent.futures


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




async def async_scan_wrapper(exec,host,port):
    event_loop = asyncio.get_running_loop()
    port_result = await event_loop.run_in_executor(exec, scanPort, host, port)
    return port_result



async def main():
    testip = input("Please enter a valid website (www.something.com) or IPv4 address (8.8.8.8)\n> ")
    userPort = input("Enter port range formatted startport,endport\nAlternatively, just press enter to scan common ports.\n> ")
    max_threads = input("Please enter the maximum number of threads allowed for scanning, or leave this blank to use the default.(50)\n> ")
    if max_threads and max_threads != 50:
        try:
            max_threads = int(max_threads)
        except:
            print("Invalid type, make sure you're entering whole numbers with no spaces.")
    else:
        max_threads = 50
    thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
    if userPort:
        #Regex to pull out the numbers from the userInput
        try:
            formattedPort = re.search(r"(\d+),(\d+)", userPort)
            startport = int(formattedPort.group(1))
            endport = int(formattedPort.group(2))

            #Assign ports to asynchronous function and run them "concurrently"
            port_list = range(startport, endport+1)
            #Give all instances of asynchronous function running on the given ports to our event loop handler
            async_tasks = [async_scan_wrapper(thread_executor,testip,port) for port in port_list]
            #Execute them 'concurrently'
            port_results = await asyncio.gather(*async_tasks)

            for port, result in port_results:
                if result == "Open":
                    print("Port %s is open. (Common Usage: %s)" % (port, common_ports.get(port, "Unknown")))
                elif result == "Closed":
                    print("Port %s is closed." % port)
                elif result == "Filtered":
                    print("Port %s is filtered." % port)
                elif result == "Status Unknown":
                    print("Port %s's status is unknown. Please scroll up to find response packet information." % port)

        except:
                print("Sorry! I didn't quite catch that, make sure your port is formatted start,end with no spaces!\nPlease restart the application.")

    #Scan common ports if no ports are provided
    else:
        #Gives the event loop handler a similar list of tasks, just using the ports in common_ports
        async_tasks = [async_scan_wrapper(thread_executor, testip,port) for port in common_ports]
        port_results = await asyncio.gather(*async_tasks)
        for port, result in port_results:
            if result == "Open":
                print("Port %s is open. (Common Usage: %s)" % (port, common_ports.get(port, "Unknown")))
            elif result == "Closed":
                print("Port %s is closed." % port)
            elif result == "Filtered":
                print("Port %s is filtered." % port)
            elif result == "Status Unknown":
                print("Port %s's status is unknown. Please scroll up to find response packet information." % port)


#I know the above code (if/elif/elif) is really ugly and not DRY
#I will fix this by making some function that can turn a port range into a list, and using it for both the common/user supplied portlist
#I'm just very tired right now.


asyncio.run(main())
