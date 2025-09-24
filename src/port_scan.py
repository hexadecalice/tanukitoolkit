from scapy.all import IP, TCP
import scapy.all as scapy

#Change testip to the ip you want to scan the ports of
#Pro-tip: You can use host_gather.py to find IP's on your network to run this tool on
testip = "8.8.8.8"

portlist = {
    20: 'FTP/Data',
    21: 'FTP/Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP/Server)',
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
def scanPort(ip, portlist):
    for port in portlist:
        #Craft initial SYN request packet, then send it and listen for one packet
        synReq = IP(dst=ip)/TCP(dport=port, flags="S")
        sendSyn = scapy.sr1(synReq, verbose=0, timeout=5)

        #Set conditionals for checking the response packet
        hasSynAck = sendSyn and sendSyn.haslayer('TCP') and sendSyn['TCP'].flags == 'SA'
        hasRst = sendSyn and sendSyn.haslayer('TCP') and "R" in sendSyn['TCP'].flags

        if hasSynAck:
            #Send RST tcp response with correct sequence and acknowledgement numbers to close the connection
            #We do this to end the connection while the TCP handshake is only half open, this makes it ~stealthier~
            rstPak = IP(dst='8.8.8.8')/TCP(sport=synReq['TCP'].sport, dport=port, seq=sendSyn['TCP'].ack, ack=sendSyn['TCP'].seq+1, flags="R")
            scapy.send(rstPak, verbose=0)
            print("Port open on port %s (%s)" % (port, portlist[port]))
        elif hasRst:
            print("Port closed on port %s " % synReq['TCP'].dport)
        elif not sendSyn:
            print("Port %s likely filtered by firewall" % synReq['TCP'].dport)
        else:
            print("Cry I guess.")
            sendSyn.show()
scanPort(testip,portlist)
