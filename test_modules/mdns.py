from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, send
import socket
import time
from utils import utilities
common_services = [
    "_http._tcp.local",     
    "_ssh._tcp.local",      
    "_ipp._tcp.local",      
    "_smb._tcp.local",      
    "_airplay._tcp.local",  
    "_workstation._tcp.local", 
    "_printer._tcp.local",  
    "_telnet._tcp.local",   
    "_ftp._tcp.local"       
]