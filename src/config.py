#PORT SCANNER
DEFAULT_THREADS = 50
PORT_TIMEOUT = 5
SEMAPHORE_LIMIT = 20
COMMON_PORTS = {
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

#ARP_SPOOFING
ARP_ATTACK_DELAY = .1
ARP_MAIN_THREAD_DELAY = 2
ROUTER_MAC = None
DOS_MAC = "00:00:00:00:00:00"

#PACKET SNIFFER
CAPTURE_DIRECTORY = "/capture/"
SCAN_FILTER = "(udp port 53 or tcp port 443)"

#HOST GATHERING
GATHER_TIMEOUT = 2

#GENERAL SETTINGS
INTERFACE = None
SUBNET = None
IP = None
