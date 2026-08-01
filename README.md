# Tanuki Toolkit
A lightweight toolkit for network analysis and security testing.

---

## Warning & Ethical Use Disclaimer

> **This tool is intended for educational purposes and authorized security testing only.**
>
> Using this tool (especially the ARP poisoning module) on any network without explicit permission from the network owner is **illegal** and unethical. The developer assumes no liability for any misuse of this software.
>
> **Please test responsibly in your own sandboxed environments.**

---

## What is this?

The Tanuki Toolkit is a small, Python-based collection of tools for network reconnaissance and testing. It's built to be a simple, command-line-driven framework for common security tasks.

### Features
* **Local Host Discovery:** See all devices on your local network.
* **Port Scanner:** Check for open ports on a target host.
* **ARP Poisoning:** Launch a Man-in-the-Middle attack to intercept traffic.

---

## Setup & Installation

### 1. Dependencies

This toolkit relies on a few key Python libraries. You can install them all using pip:

```bash
pip install -r requirements.txt
```

**For Windows Users:** Scapy requires npcap for many of it's functions execution. If you're running into weird errors, ensure this is installed.

### 2. Administrator Privileges (CRITICAL!)

> **To send and receive raw packets (which is how this *entire* toolkit works), you must run it with administrative or root privileges.**

* **On Windows:** Run your terminal (CMD/PowerShell) as **Administrator**.
* **On macOS/Linux:** Use `sudo`.

```bash
sudo python tanuki.py [your-commands]
```

---

## How to Use

All commands are run from the main `tanuki.py` launcher.

### The Help Menu (Start Here!)

To see a full list of all available commands and what they do, just ask for help:

```bash
python tanuki.py -h
```

Additionally, for all following commands you can specify an interface by which to scan using the `-i` flag:

```bash
python tanuki.py -someflag -i your_interface
```

### 1. Local Host Discovery (`-lh`)

Want to see who's on your Wi-Fi? This command scans your local subnet and prints a list of all connected devices.

**Command:**

```bash
# On Windows (in Admin terminal)
python tanuki.py -lh

# On Linux/macOS
sudo python tanuki.py -lh
```

**Example Output:**

```text
IP Address: 192.168.1.1
Mac Address: 11:22:33:AA:BB:CC
Manufacturer: Netgear
Host Name (Usually undetermined): router.local

IP Address: 192.168.1.10
Mac Address: AA:BB:CC:44:55:66
Manufacturer: Apple, Inc.
Host Name (Usually undetermined): Jerrys-iPhone
```

### 2. Port Scanning (`-ps`)

This module lets you check a target for open ports. You **must** provide a target IP or hostname (`-ip`).

**Example 1: Scan a target for common ports**
This uses the built-in list of common ports.

```bash
# (Remember to use sudo/Admin!)
python tanuki.py -ps -ip 192.168.1.1
```

**Example 2: Scan a specific port range**
Use `-pr` to define a range, formatted as `start,end`.

```bash
python tanuki.py -ps -ip scanme.nmap.org -pr 20,80
```

**Example 3: Scan faster (more threads) and with a shorter timeout**
Use `-t` to set the thread count and `-w` to set the timeout in seconds.

```bash
python tanuki.py -ps -ip 192.168.1.1
