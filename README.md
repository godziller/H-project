# Network Scanner and Open Port finding Tool
#### https://drive.google.com/file/d/185Vv2SABt-VXhZnrlSlMSYMMevKVQoWr/view?usp=sharing
#### Description:

this is a Python based network reconnaissance tool that provides two core functionalities.

1. **ARP-based Network Discovery**
2. **TCP port scanning**

These capabilities allow users to identify active devices on a local subnet and determine which ports are open on a target machine. The tool is designed for educational and diagnostic use, such as understanding how ARP works or checking open services during development or testing environments.

---

## Features

### 🔍 ARP Network Scanner

- Utilizes raw sockets and constructs custom ARP packets.
- Sends broadcast ARP requests to each IP in a `/24` subnet (e.g., 192.168.1.0–192.168.1.255).
- Collects ARP replies to discover live hosts and their MAC addresses.
- Interface information (IP and MAC) is automatically retrieved using low-level socket operations.

### 📡 TCP Port Scanner

- Scans all 65,535 TCP ports on a given IP address.
- Employs multithreading via Python’s `concurrent.futures.ThreadPoolExecutor` for high performance.
- Reports which ports are open by attempting to establish TCP connections.
- Fast and efficient — completes full scan in seconds on most local networks.

---

## How to Use

Run with root privileges:

```bash
sudo python3 project.py scan   # Performs ARP scan on local subnet
sudo python3 project.py targ   # Prompts for IP and runs full TCP port scan
