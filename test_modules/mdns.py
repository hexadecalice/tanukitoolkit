from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, send
import socket
import time
from utils import utilities
common_services = [
    "_http._tcp.local",     # Web servers
    "_ssh._tcp.local",      # SSH remote shells
    "_ipp._tcp.local",      # Network printers
    "_smb._tcp.local",      # File shares
    "_airplay._tcp.local",  # Media streaming
    "_workstation._tcp.local", # General device discovery
    "_printer._tcp.local",  # Legacy printer discovery
    "_telnet._tcp.local",   # Telnet (rare, but still exists)
    "_ftp._tcp.local"       # FTP servers
]