# Tanuki Toolkit 🦝
A lightweight toolkit for network analysis and security testing.



---

## ⚠️ Warning & Ethical Use Disclaimer ⚠️

This tool is intended for **educational purposes and authorized security testing only**.

Using this tool (especially the ARP poisoning module) on any network without explicit permission from the network owner is **illegal** and unethical. The developer assumes no liability for any misuse of this software.

**Please test responsibly in your own sandboxed environments.**

---

## What is this?

The Tanuki Toolkit is a small, Python-based collection of tools for network reconnaissance and testing. It's built to be a simple, command-line-driven framework for common security tasks.

### Features
* 📡 **Local Host Discovery:** See all devices on your local network.
* 🚪 **Port Scanner:** Check for open ports on a target host.
* 🎭 **ARP Poisoning:** Launch a Man-in-the-Middle (MITM) attack to intercept traffic (for analysis).

---

## 🚨 Setup & Installation 🚨

### 1. Dependencies

This toolkit relies on a few key Python libraries. You can install them all using pip:

    pip install scapy netifaces getmac mac-vendor-lookup

### 2. Administrator Privileges (CRITICAL!)

To send and receive raw packets (which is how this *entire* toolkit works), you **must** run it with administrative or root privileges.

* **On Windows:** Run your terminal (CMD/PowerShell) as **Administrator**.
* **On macOS/Linux:** Use `sudo`.

        sudo python tanuki.py [your-commands]

---

## How to Use 🦝

All commands are run from the main `tanuki.py` launcher.

### The Help Menu (Start Here!)

To see a full list of all available commands and what they do, just ask for help:

    python tanuki.py -h

### 1. Local Host Discovery (`-lh`)

Want to see who's on your Wi-Fi? This command scans your local subnet and prints a list of all connected devices.

**Command:**

    # On Windows (in Admin terminal)
    python tanuki.py -lh

    # On Linux/macOS
    sudo python tanuki.py -lh

**Example Output:**

    IP Address: 192.168.1.1
    Mac Address: 11:22:33:AA:BB:CC
    Manufacturer: Netgear
    Host Name (Usually undetermined): router.local

    IP Address: 192.168.1.10
    Mac Address: AA:BB:CC:44:55:66
    Manufacturer: Apple, Inc.
    Host Name (Usually undetermined): Jerrys-iPhone

### 2. Port Scanning (`-ps`)

This module lets you check a target for open ports. You **must** provide a target IP or hostname (`-ip`).

**Example 1: Scan a target for common ports**
This uses the built-in list of common ports.

    # (Remember to use sudo/Admin!)
    python tanuki.py -ps -ip 192.168.1.1

**Example 2: Scan a specific port range**
Use `-pr` to define a range, formatted as `start,end`.

    python tanuki.py -ps -ip scanme.nmap.org -pr 20,80

**Example 3: Scan faster (more threads) and with a shorter timeout**
Use `-t` to set the thread count and `-w` to set the timeout in seconds.

    python tanuki.py -ps -ip 192.168.1.1 -pr 1,1000 -t 100 -w 0.5

### 3. ARP Poisoning / MITM Attack (`-arp`)

**Read the warning at the top again before using this tool.**

This module will launch an ARP poisoning attack against a specific target on your local network, fooling both the target and your router into sending traffic through your machine.

You **must** provide the target's IP (`-ip`) and their MAC address (`-tm`).

**Command:**

    # (Remember to use sudo/Admin!)
    python tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff

The toolkit will try to find your router's MAC address automatically. If it fails, you can specify it manually with the `-rm` flag:

    python tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff -rm 11:22:33:44:55:66

---

## All Commands (Quick Reference)

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Shows the help message. |
| `-lh`| `--local_hosts` | Prints IP/MAC addresses of local devices. |
| `-ps`| `--port_scan` | Runs the port scanner. Requires `-ip`. |
| `-arp`| `--arp_poison` | Starts the ARP MITM attack. Requires `-ip` and `-tm`. |
| `-ip`| `--target-ip` | Specifies the target's IP or hostname. |
| `-pr`| `--port_range` | Port range for scanning, e.g., `1,1000`. |
| `-t` | `--thread_maximum`| Max threads for the port scanner. (Default: 50) |
| `-w` | `--wait` | Port scan timeout in seconds. (Default: 3) |
| `-tm`| `--target_mac` | **Required for ARP.** The target's MAC address. |
| `-rm`| `--router_mac` | **Optional for ARP.** Manually specify the router's MAC. |