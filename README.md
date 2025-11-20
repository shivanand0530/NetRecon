# NetRecon - Network Security Scanner

> Advanced network reconnaissance and vulnerability assessment tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

##  What It Does

NetRecon scans networks to discover devices, identify open ports, detect running services, and flag known vulnerabilities. Perfect for security audits and network administration.

## Features

- **Device Discovery** - Find all live hosts via ping/ARP scanning
- **OS Fingerprinting** - Identify operating systems using TTL analysis
- **Port Scanning** - Detect open ports and running services
- **Banner Grabbing** - Extract service versions (HTTP, SSH, FTP, etc.)
- **Vulnerability Detection** - Cross-reference with CVE database
- **Multi-Format Reports** - Export as HTML, Markdown, JSON, or CLI tables
- **Real-Time Alerts** - Discord notifications for critical findings

## 🚀 Quick Start

```bash
# Install dependencies
pip install requests tabulate psutil scapy

# Basic scan
python netrecon.py -n 192.168.1.0/24

# Generate HTML report
python netrecon.py -n 192.168.1.0/24 -o html

# Create sample config
python netrecon.py --create-config
```

## 📋 Usage

```bash
python netrecon.py -n <network> [options]

Options:
  -n, --network      Target network (e.g., 192.168.1.0/24)
  -o, --output       Output format: table, html, markdown, json
  -c, --config       Configuration file path
  --all-ports        Scan all ports (1-1024)
  --create-config    Generate sample config file
```

## 📊 Example Output

```
╒══════════════╤════════════╤════════════╤════════════╤══════════════╕
│ IP           │ Hostname   │ OS         │ Open Ports │ Vulnerabilities │
╞══════════════╪════════════╪════════════╪════════════╪══════════════╡
│ 192.168.1.1  │ router     │ Linux/Unix │ 2          │ 0            │
│ 192.168.1.50 │ webserver  │ Linux/Unix │ 3          │ 2 (1 HIGH)   │
╘══════════════╧════════════╧════════════╧════════════╧══════════════╛

[!] HIGH SEVERITY: CVE-2021-41773 found on 192.168.1.50
```

##  Configuration

Edit `netrecon_config.json`:

```json
{
  "scan_delay": 0.1,
  "scan_all_ports": false,
  "notifications": true,
  "discord_webhook": "YOUR_WEBHOOK_URL"
}
```

## Legal Disclaimer

**For authorized testing only.** Only scan networks you own or have explicit written permission to test. Unauthorized scanning is illegal.

##  Requirements

- Python 3.8+
- `requests`, `tabulate`, `psutil` (required)
- `scapy` (optional, for advanced features)

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**⚡ Security Testing Made Simple**
