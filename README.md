# TanukiToolkit 🦝

A lightweight collection of network analysis and penetration testing tools, built for educational purposes and hands-on learning.

This project was created to explore the fundamentals of network protocols and cybersecurity principles by building simple, functional tools from the ground up. It's a work in progress, and far from optimal (or good, honestly).

---

## 🛠️ Tools Included

* **Network Scanner (`host_gather.py`):** Discovers all active devices on your local network using ARP broadcasts.
* **Port Scanner (`port_scan.py`):** Checks for open TCP ports on a target host using a TCP SYN "stealth" scan.
* **Shitty Packet Sniffer (`scanner.py`):** Overall useless program that scans your own dns data
---

## 🚀 Getting Started

Follow these instructions to get the toolkit running on your local machine.

### Prerequisites

* Python 3.x
* Pip package manager

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/hexadecalice/tanukitoolkit.git](https://github.com/hexadecalice/tanukitoolkit.git)
    cd tanukitoolkit
    ```

2.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

    > **Troubleshooting Note ⚠️**
    > The `netifaces` package requires a C++ compiler. If you encounter errors during installation on Windows, you may need to install the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/). On Linux or macOS, ensure you have `build-essential` or Xcode Command Line Tools installed.

---

## Usage

-   **To scan a target:**
    ```
    python port_scan.py -ip www.yourwebsite.com -p startport,endport
    ```
-   If a port range is not included, the scanner will check a default list of commonly used ports.
-   If a maximum thread count is not included, the default is 50.
-   You can use `-lh` as a lone flag to find local devices on the network.
-   For a list of all flags, use `python port_scan.py -h`.
-   If you'd like to run `host_gather.py` as a standalone, just run `python host_gather.py`.

> **Troubleshooting Note ⚠️**
>
> If you're encountering `OSError: Bad File Descriptor` or `OSError: Invalid Argument` frequently, try reducing the thread count. 
>
> This error occurs due to a race condition, caused by two internal scapy threads try to access the same resource. (I think)
>
> To my knowledge, this is basically unfixable. But if you have any good solutions, please feel free to open an issue or pull request.


