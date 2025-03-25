# Network Scanner 🔍🌐

## 🌟 Overview

A Python script for performing ARP scans on local networks to discover active hosts. Uses Scapy for efficient network probing and provides clear output of connected devices.

## ✨ Features

- 🖥️ Automatic IP address detection
- 🌍 Network range validation
- 📡 ARP scanning capabilities
- 📋 Clean tabular results display
- ⚡ Fast host discovery
- 🛡️ Error handling for invalid inputs

## 🚀 Prerequisites

- Python 3.x
- Linux/macOS (or Windows with adjustments)
- Scapy library (`pip install scapy`)
- Root/Sudo privileges (for raw packet operations)
- `optparse`, `subprocess`, and `re` modules

## 💻 Usage

```bash
sudo python Network_Scanner.py -r <network_range>
```

### Examples

- Scan local subnet: `sudo python Network_Scanner.py -r 192.168.1.0/24`

## 🛠️ Command-line Options

| Option          | Description              |
| --------------- | ------------------------ |
| `-r`, `--range` | Network IP range to scan |
| `-h`, `--help`  | Shows help information   |

## ⚠️ Important Notes

- Requires root/sudo permissions for raw socket operations
- May trigger security alerts on monitored networks
- Scans only IPv4 networks
- Results include IP and MAC addresses of active hosts
- Timeout is set to 1 second (adjustable in code)

## 📊 Sample Output

```
-------------------------------------------------
[i] IP address              MAC address
-------------------------------------------------
[1] 192.168.1.1            00:11:22:33:44:55
[2] 192.168.1.15           aa:bb:cc:dd:ee:ff
```
