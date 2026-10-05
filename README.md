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
* **Local Host Discovery:** See devices on your local network.
* **Port Scanner:** Check for open ports on a target host.
* **ARP Poisoning:** Launch a Man-in-the-Middle test in an authorized lab and capture redirected traffic.

---

## Setup & Installation

### 1. Python Dependencies

This toolkit relies on a few key Python libraries. You can install them all using pip:

```bash
pip install -r requirements.txt
```

A virtual environment is recommended:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Native Packet-Capture Requirements

Tanuki's ARP module uses a native packet-sniffing utility written in C with **libpcap**. The C source is included in `src/modules/binaries/`.

Precompiled packet-capture binaries are currently provided for:

* **Linux x86-64**
* **Windows x86-64**

**Linux:** The libpcap runtime must be installed. Building the sniffer from source also requires the libpcap development headers and a C compiler.

**Windows:** Install **Npcap**. Scapy and the native capture utility depend on packet-capture support provided by Npcap.

**macOS and ARM:** A compatible precompiled sniffer binary is not currently distributed. The included C source may be compiled for the target platform, but packet-capture support on these systems should currently be considered experimental.

The bundled Linux executable is an x86-64 ELF binary. It will not run natively on ARM systems, and Linux binaries are not native macOS executables even when both machines use the same CPU architecture.

### 3. Administrator Privileges (CRITICAL!)

> **To send and receive raw packets, Tanuki generally must be run with administrative or root privileges.**

* **On Windows:** Run your terminal (CMD/PowerShell) as **Administrator**.
* **On Linux/macOS:** Use `sudo` where raw packet access is required.

Commands in this README assume they are being run from the repository root.

```bash
sudo python src/tanuki.py [your-commands]
```

---

## How to Use

All commands are run from the main `src/tanuki.py` launcher.

### The Help Menu (Start Here!)

To see a full list of all available commands and what they do:

```bash
python src/tanuki.py -h
```

Additionally, for all following commands you can specify an interface by which to scan using the `-i` flag:

```bash
python src/tanuki.py -someflag -i your_interface
```

### 1. Local Host Discovery (`-lh`)

This command scans your local subnet and prints a list of discovered devices.

**Command:**

```bash
# On Windows (in Admin terminal)
python src/tanuki.py -lh

# On Linux/macOS
sudo python src/tanuki.py -lh
```

Discovery results are saved under the repository's `device_data/` directory and separated by interface so they can later be reused by the ARP module.

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
# Remember to use sudo/Admin where raw packet access requires it.
sudo python src/tanuki.py -ps -ip 192.168.1.1
```

**Example 2: Scan a specific port range**

Use `-pr` to define a range, formatted as `start,end`.

```bash
sudo python src/tanuki.py -ps -ip 192.168.1.10 -pr 20,80
```

If an invalid value is supplied to `-pr`, Tanuki prints a warning and falls back to its built-in common-port list rather than silently changing behavior.

**Example 3: Scan faster (more threads) and with a shorter timeout**

Use `-t` to set the thread count and `-w` to set the timeout in seconds.

```bash
sudo python src/tanuki.py -ps -ip 192.168.1.10 -pr 1,1000 -t 100 -w 0.5
```

### 3. ARP Poisoning / MITM Attack (`-arp`)

> **Read the warning at the top again before using this tool. Only use this module against systems and networks you own or are explicitly authorized to test.**

This module performs ARP poisoning against a target on the local network so that traffic can be redirected through the machine running Tanuki. When supported by the host platform, the bundled native sniffer captures observed traffic to PCAP.

You **must** provide the target's IP (`-ip`) and MAC address (`-tm`) unless you reuse previously discovered hosts with `-r`.

**Command:**

```bash
sudo python src/tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff
```

The toolkit will try to find your router's MAC address automatically. If it fails, you can specify it manually with the `-rm` flag:

```bash
sudo python src/tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff -rm 11:22:33:44:55:66
```

**Host Discovery Integration**

By using the `-r` flag, you can utilize previously discovered hosts.
If you run `-arp` with the `-r` flag set (optionally with `-i`), Tanuki loads the devices previously discovered by `-lh` for that interface from the generated JSON data file.

From there, you can select one of the discovered hosts from a list. For most lab use cases, this is the easiest way of running the ARP module.

> **A quick word of warning:** If you're working on an interface other than the default interface, specify it with `-i` both when performing discovery and when later loading that interface's saved hosts.

```bash
# Returns hosts found by -lh when run on your default interface
sudo python src/tanuki.py -arp -r

# Returns hosts found by -lh on this interface
sudo python src/tanuki.py -arp -r -i wlan0
```

**Troubleshooting: Enabling IP Forwarding**

If your target loses connectivity during an authorized MITM lab, your machine may not be forwarding the traffic onward. IP forwarding must be configured appropriately on the machine running Tanuki.

* **On Linux:** `echo 1 > /proc/sys/net/ipv4/ip_forward`
* **On macOS:** `sudo sysctl -w net.inet.ip.forwarding=1`
* **On Windows (Admin PowerShell):** `Set-NetIPInterface -Forwarding Enabled`
  *(You may also need to enable/start the "Routing and Remote Access" service.)*

The native packet-capture feature is currently dependent on a compatible sniffer binary for the host OS/CPU architecture. If the binary is missing or cannot be started, Tanuki should report that condition rather than crashing the Python process.

---

### 4. Denial of Service (`-dos`)

If your goal in an authorized lab is to test loss of connectivity rather than capture redirected traffic, the `-dos` flag changes the poisoning behavior.

Additionally, the module attempts to affect IPv6 neighbor/router state using the IPv6 logic described below.

This has been implemented with limited success and should be considered experimental.

**Command:**

```bash
sudo python src/tanuki.py -arp -ip 192.168.1.10 -tm aa:bb:cc:dd:ee:ff -dos
```

It specifically attempts to:

1. **Suppress Router Advertisements (RA):** Sends targeted router advertisements with the router lifetime field set to 0.
2. **Spoof Neighbor Advertisements (NA):** Attempts to overwrite the target's neighbor cache with a nonsense MAC.
3. **Spoof the ARP table:** Associates the router address with a nonsense MAC for the target.

---

## Notes for nerds

If you happen to be toying around with the source code, here's a few quick notes:
A lot of the main functions for generating your IP, subnet, etc. are found in `utilities.py`. This is just for code cleanliness.
Things like error messages, jitter, timeouts, etc. are kept inside `config.py`.
If you'd like to change the program's functionality past what's permitted in flags, those are the places to look.

The ARP spoofing module uses a packet-sniffing engine written in C and currently includes compiled Linux x86-64 and Windows x86-64 binaries.
This was done mainly to improve performance compared to the original design, which used Scapy's native `sniff()` function.
Tanuki's ARP module uses `subprocess.Popen()` to call the executable, then passes the BPF string and interface as arguments.

The binary path is resolved relative to the source tree rather than the shell's current working directory.

It handles teardown via a `threading.Event()`, which triggers a `SIGINT` sent to the binary when the ARP module is stopped.
The binary handles the signal by closing its sniffing loop and exiting.
The actual packet-sniffing logic is written using libpcap, and the source code is included in the binaries folder.

Because native executables are platform- and architecture-specific, additional builds are required for targets such as macOS or Linux ARM64.

---

## AI Disclosure

Throughout the course of this project I have used generative AI in a limited capacity. It was used to generate the instructional parts of this README, and outside of that I've used it primarily as a code formatter when I felt the source files were getting a bit too unruly. It's also been a fantastic research tool, and especially in the beginning of this project it was used to parse Scapy and Netifaces documentation, along with a few (incredibly verbose) networking books I had picked up to aid in my learning. However, it's worth stating that the code, logic, architecture, etc. were written manually by me and me alone.

---

## Other Notes & Thanks

This project was one I undertook to try to better understand networks and network security; it is far from a professional toolkit.
I apologize for the breadth of seemingly unneeded comments. Some of you may relate to the fact that, especially when undertaking a new topic, it's easy to lose track of what you've learned. I left these comments as reminders to myself so that I don't lose track of key concepts, but I understand that they come across as a bit much.

Thank you to anyone who clones or even glances through this project. It's really reignited a passion in me for networks and security. For as many flaws as it has, it's something I'm pretty proud of. I welcome any questions/issues/criticisms, and thanks so much for reading!

---

## All Commands (Quick Reference)

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Shows the help message. |
| `-i` | `--interface` | Specifies which interface to act on. |
| `-lh` | `--local_hosts` | Prints IP/MAC addresses of local devices. |
| `-ps` | `--port_scan` | Runs the port scanner. Requires `-ip`. |
| `-arp` | `--arp_poison` | Starts the ARP MITM test. Requires `-ip` and `-tm` unless using `-r`. |
| `-ip` | `--target-ip` | Specifies the target's IP or hostname. |
| `-pr` | `--port_range` | Port range for scanning, e.g. `1,1000`. Invalid input warns and falls back to common ports. |
| `-t` | `--thread_maximum` | Max threads for the port scanner. (Default: 50) |
| `-w` | `--wait` | Port scan timeout in seconds. (Default: 3) |
| `-tm` | `--target_mac` | The target's MAC address. Required for ARP spoofing unless using the `-r` flag. |
| `-rm` | `--router_mac` | **Optional for ARP.** Manually specify the router's MAC. |
| `-dos` | `--dos_target` | **Optional / experimental.** Changes poisoning behavior to disrupt connectivity in an authorized lab. |
| `-r` | `--read_device_file` | **Optional for ARP.** Loads hosts from a previous `-lh` discovery instead of requiring manual target entry. |