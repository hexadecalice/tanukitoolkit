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
python tanuki.py -ps -ip 192.168.1.1 -pr 1,1000 -t 100 -w 0.5
```

### 3. ARP Poisoning / MITM Attack (`-arp`)

> **Read the warning at the top again before using this tool.**

This module will launch an ARP poisoning attack against a specific target on your local network, fooling both the target and your router into sending traffic through your machine.

You **must** provide the target's IP (`-ip`) and their MAC address (`-tm`).

**Command:**

```bash
# (Remember to use sudo/Admin!)
python tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff
```

The toolkit will try to find your router's MAC address automatically. If it fails, you can specify it manually with the `-rm` flag:

```bash
python tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff -rm 11:22:33:44:55:66
```

**Host Discovery Integration**

By using the `-r` flag, you can utiltize previously discovered hosts. 
If you run `-arp` with only the `-r` flag set (or additionally, with the `-i` flag), it'll pull hosts discovered by `-lh` from a generated JSON file.

These JSON files are saved according to interface scanned e.g device_data-wlan0, device_data-eth0, etc. 

From there, you can select one of the discovered hosts from a list. For most use cases, this is the easiest way of running the ARP module.

> **A quick word of warning:** Always ensure if you're trying to spoof hosts outside your default interface, you specify this with the ` -i` flag, for example: 

```bash
# Returns hosts found by -lh when run on your default interface (without -i)
sudo tanuki.py -arp -r

# Returns hosts found by -lh on that interface (if file doesn't exist, run -lh with target interface specified)
sudo tanuki.py -arp -r -i wlan0
```

**Troubleshooting: Enabling IP Forwarding**

If your target loses internet connection, it's because your machine is not forwarding their packets to the router. You must enable IP forwarding on your *attacking* machine.

* **On Linux:** 
  `echo 1 > /proc/sys/net/ipv4/ip_forward`
* **On macOS:** 
  `sudo sysctl -w net.inet.ip.forwarding=1`
* **On Windows (Admin PowerShell):** 
  `Set-NetIPInterface -Forwarding Enabled`
  *(You may also need to enable/start the "Routing and Remote Access" service)*

---

### 4. Denial of Service (`-dos`)

If your goal is to disconnect a target from the internet entirely rather than just sniffing their traffic, you can use the `-dos` flag. 

When enabled, the toolkit will flood the target with unsolicited ARP replies linking the gateway's IP address with a nonsense MAC. 

Additionally, it also attempts to poison the target's neighbor cache with router/neighbor advertisements as specified below.

This has been implemented with...limited success. It works sometimes. But, fixes soon to come!

**Command:**

```bash
# (Remember to use sudo/Admin!)
python tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff -dos
```

It specifically:
1. **Suppresses Router Advertisements (RA):** Sends targeted router advertisements with the router lifetime field set to 0
2. **Spoofs Neighbor Advertisements (NA):** Overwrites the target's neighbor cache to redirect IPv6 traffic into a nonsense MAC.
3. **Spoofs ARP table:** Overwrites target's ARP tables, changing the router's MAC to 00:00:00:00:00:00

---

## Notes for nerds

If you happen to be toying around with the source code, heres a few quick notes:
A lot of the main functions for generating your IP, subnet, etc are found in utilities.py. This is just for code cleanliness.
Things like error messages, jitter, timeouts, etc. are kept inside of config.py.
If you'd like to change the program's functionality past what's permitted in flags, those are the places to look.

The ARP spoofing module uses a packet sniffing engine written in C and compiled into both a native Linux binary and a Windows executable. 
This was done mainly to improve performance compared to the original design which used Scapy's native sniff() function. 
Tanuki's ARP module uses subprocess' popen() to call the exectuable, then passes the BPF string and interface as arguments. 

It handles teardown via a threading.Event(), which when set triggers a SIGINT sent to the binary.
The binary handles the signal by closing its sniffing loop and exiting.
The actual packet sniffing logic is written using libpcap, the source code is included in the binaries folder. 

---

## AI Disclosure

Throughout the course of this project I have used generative AI in a limited capacity. It was used to generate the instructional parts of this README, and outside of that I've used it primarily as a code formatter when I felt the source files were getting a bit too unruly. It's also been a fantastic research tool, and especailly in the beginning of this project it was used to parse Scapy and Netifaces documentation, along with a few (incredibly verbose) networking books I had picked up to aid in my learning. However, its worth stating that the code, logic, architecture, etc were written manually by me and me alone. 

---

## Other Notes & Thanks 

This project was one I undertook to try to better understand networks and network security, it is far from a professional toolkit. 
I apologize for the breadth of seemingly unneeded comments, some of you may relate to the fact that (especially when undertaking a new topic) it's easy to lose track of what you've learned. I left these comments as reminders to myself so that I don't lose track of key concepts, but I understand that they come across as a bit much.

Thank you to anyone who clones or even glances through this project, its really reignited a passion in me for networks and security. For as many flaws as it has, it's something I'm pretty proud of. I welcome any questions/issues/criticisms, and thanks so much for reading!

---

## All Commands (Quick Reference)

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Shows the help message. |
| `-i` | `--interface` | Specifies which interface to act on. |
| `-lh`| `--local_hosts` | Prints IP/MAC addresses of local devices. |
| `-ps`| `--port_scan` | Runs the port scanner. Requires `-ip`. |
| `-arp`| `--arp_poison` | Starts the ARP MITM attack. Requires `-ip` and `-tm`. |
| `-ip`| `--target-ip` | Specifies the target's IP or hostname. |
| `-pr`| `--port_range` | Port range for scanning, e.g., `1,1000`. |
| `-t` | `--thread_maximum`| Max threads for the port scanner. (Default: 50) |
| `-w` | `--wait` | Port scan timeout in seconds. (Default: 3) |
| `-tm`| `--target_mac` | The target's MAC address. Required for ARP spoofing unless using the `-r` flag. |
| `-rm`| `--router_mac` | **Optional for ARP.** Manually specify the router's MAC. |
| `-dos`| `--dos_target` | **Optional for ARP.** Set ARP spoofed MAC to 00:00:00:00:00, cutting target's internet. |
| `-r`| `--read_device_file` | **Optional for ARP.** If you've recently run the host discovery, it lists those devices as options for scanning instead of requiring manual entry. |
