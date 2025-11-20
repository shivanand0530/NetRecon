#!/usr/bin/env python3
"""
NetRecon - Advanced Network Reconnaissance and Security Scanner
A comprehensive CLI tool for network security assessment and vulnerability detection.

LEGAL DISCLAIMER: This tool is intended for authorized security testing and 
network administration purposes only. Use only on networks you own or have 
explicit written permission to test.
"""

import argparse
import asyncio
import json
import random
import socket
import struct
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import ipaddress
import re
import requests
from dataclasses import dataclass, asdict


try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, ICMP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some advanced features will be limited.")

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    print("Warning: tabulate not available. Installing: pip install tabulate")

try:
    import netifaces # type: ignore
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class ScanResult:
    """Data class for storing scan results"""
    ip: str
    hostname: str = ""
    os_fingerprint: str = ""
    mac_address: str = ""
    open_ports: List[int] = None
    services: Dict[int, str] = None
    vulnerabilities: List[Dict] = None
    scan_time: str = ""
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if not self.scan_time:
            self.scan_time = datetime.now().isoformat()


class NetworkScanner:
    """Main network scanner class"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.results: List[ScanResult] = []
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                           443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        self.os_signatures = {
            64: "Linux/Unix",
            128: "Windows",
            255: "Linux (older)",
            32: "Windows 95/98",
            60: "MacOS"
        }
        
    def get_network_interface(self) -> str:
        """Get the default network interface with Windows compatibility"""
        # Try psutil first (more reliable cross-platform)
        if PSUTIL_AVAILABLE:
            try:
                interfaces = psutil.net_if_addrs()
                for interface_name, interface_addresses in interfaces.items():
                    for address in interface_addresses:
                        if address.family == socket.AF_INET and not address.address.startswith('127.'):
                            return interface_name
            except Exception:
                pass
        
        # Try netifaces if available
        if NETIFACES_AVAILABLE:
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
                if default_gateway:
                    return default_gateway[1]
                
                # Fallback to first available interface
                interfaces = netifaces.interfaces()
                for iface in interfaces:
                    if iface != 'lo':  # Skip loopback
                        return iface
            except Exception:
                pass
        
        # Windows/cross-platform fallback
        import platform
        if platform.system() == "Windows":
            return "Local Area Connection"  # Common Windows interface name
        else:
            return "eth0"  # Default Linux fallback
    
    def ping_sweep(self, network: str) -> List[str]:
        """Perform ICMP ping sweep to discover live hosts with Windows compatibility"""
        live_hosts = []
        network_obj = ipaddress.IPv4Network(network, strict=False)
        
        print(f"[*] Performing ping sweep on {network}")
        
        def ping_host(ip):
            try:
                import platform
                if platform.system() == "Windows":
                    # Windows ping command
                    result = subprocess.run(
                        ['ping', '-n', '1', '-w', '1000', str(ip)], 
                        capture_output=True, 
                        timeout=3
                    )
                else:
                    # Unix/Linux ping command
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', str(ip)], 
                        capture_output=True, 
                        timeout=2
                    )
                
                if result.returncode == 0:
                    return str(ip)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            return None
        
        # Use ThreadPoolExecutor for concurrent pings
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in network_obj.hosts()}
            for future in futures:
                result = future.result()
                if result:
                    live_hosts.append(result)
                    print(f"[+] Live host found: {result}")
        
        return live_hosts
    
    def arp_scan(self, network: str) -> List[Tuple[str, str]]:
        """Perform ARP scan for device discovery"""
        if not SCAPY_AVAILABLE:
            print("[-] ARP scan requires Scapy. Skipping...")
            return []
        
        print(f"[*] Performing ARP scan on {network}")
        devices = []
        
        try:
            # Create ARP request
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packets and receive responses
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                devices.append((ip, mac))
                print(f"[+] Device found: {ip} ({mac})")
                
        except Exception as e:
            print(f"[-] ARP scan failed: {e}")
            
        return devices
    
    def os_fingerprint_ttl(self, ip: str) -> str:
        """Perform passive OS fingerprinting using TTL values with Windows compatibility"""
        try:
            if SCAPY_AVAILABLE:
                # Send ICMP ping and analyze TTL
                response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
                if response:
                    ttl = response[IP].ttl
                    return self.os_signatures.get(ttl, f"Unknown (TTL: {ttl})")
            else:
                # Fallback method using system ping
                import platform
                if platform.system() == "Windows":
                    result = subprocess.run(
                        ['ping', '-n', '1', ip], 
                        capture_output=True, 
                        text=True, 
                        timeout=3
                    )
                    # Windows ping output format
                    ttl_match = re.search(r'TTL=(\d+)', result.stdout)
                else:
                    result = subprocess.run(
                        ['ping', '-c', '1', ip], 
                        capture_output=True, 
                        text=True, 
                        timeout=3
                    )
                    # Unix/Linux ping output format
                    ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                
                if result.returncode == 0 and ttl_match:
                    ttl = int(ttl_match.group(1))
                    return self.os_signatures.get(ttl, f"Unknown (TTL: {ttl})")
        except Exception as e:
            print(f"[-] OS fingerprinting failed for {ip}: {e}")
        
        return "Unknown"
    
    def syn_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Perform SYN scan using Scapy"""
        if not SCAPY_AVAILABLE:
            return self.tcp_connect_scan(ip, ports)
        
        open_ports = []
        
        # Randomize port order if configured
        if self.config.get('randomize_ports', False):
            ports = ports.copy()
            random.shuffle(ports)
        
        print(f"[*] SYN scanning {ip}")
        
        try:
            # Optional MAC spoofing
            src_mac = None
            if self.config.get('spoof_mac', False):
                src_mac = "02:00:00:00:00:01"  # Simple MAC spoof
            
            for port in ports:
                try:
                    # Create SYN packet
                    syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
                    if src_mac:
                        syn_packet = Ether(src=src_mac) / syn_packet
                    
                    # Send packet and wait for response
                    response = sr1(syn_packet, timeout=1, verbose=False)
                    
                    if response and TCP in response:
                        if response[TCP].flags == 18:  # SYN-ACK
                            open_ports.append(port)
                            print(f"[+] Port {port} open on {ip}")
                            
                            # Send RST to close connection gracefully
                            rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                            send(rst_packet, verbose=False)
                    
                    # Configurable timing delay
                    if self.config.get('scan_delay', 0) > 0:
                        time.sleep(self.config['scan_delay'])
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"[-] SYN scan failed for {ip}: {e}")
        
        return open_ports
    
    def tcp_connect_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Fallback TCP connect scan"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        # Use threading for concurrent scans
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"[+] Port {result} open on {ip}")
        
        return open_ports
    
    def banner_grab(self, ip: str, port: int) -> str:
        """Grab service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 22:  # SSH
                pass  # SSH sends banner immediately
            elif port == 21:  # FTP
                pass  # FTP sends banner immediately
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception as e:
            return f"Banner grab failed: {e}"
    
    def check_vulnerabilities(self, service_info: str, port: int) -> List[Dict]:
        """Cross-reference service with CVE database"""
        vulnerabilities = []
        
        if not service_info or "failed" in service_info.lower():
            return vulnerabilities
        
        # Extract version information
        version_patterns = [
            r'Apache[/\s]+(\d+\.\d+\.\d+)',
            r'nginx[/\s]+(\d+\.\d+\.\d+)',
            r'OpenSSH[_\s]+(\d+\.\d+)',
            r'vsftpd[/\s]+(\d+\.\d+\.\d+)',
            r'Microsoft[^0-9]*(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, service_info, re.IGNORECASE)
            if match:
                version = match.group(1)
                service_name = pattern.split('[')[0].strip('r\'')
                
                # Simulate CVE lookup (in real implementation, use NVD API)
                vuln = self.mock_cve_lookup(service_name, version)
                if vuln:
                    vulnerabilities.append(vuln)
                break
        
        return vulnerabilities
    
    def mock_cve_lookup(self, service: str, version: str) -> Optional[Dict]:
        """Mock CVE lookup - replace with real NVD API in production"""
        # Common vulnerable versions for demonstration
        known_vulns = {
            ('Apache', '2.4.49'): {
                'cve': 'CVE-2021-41773',
                'severity': 'HIGH',
                'score': 9.8,
                'description': 'Path traversal vulnerability'
            },
            ('nginx', '1.18.0'): {
                'cve': 'CVE-2021-23017',
                'severity': 'MEDIUM', 
                'score': 5.3,
                'description': 'DNS resolver off-by-one heap write'
            },
            ('OpenSSH', '7.4'): {
                'cve': 'CVE-2018-15473',
                'severity': 'MEDIUM',
                'score': 5.3,
                'description': 'Username enumeration vulnerability'
            }
        }
        
        return known_vulns.get((service, version))
    
    def resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return ""
    
    def scan_network(self, network: str) -> None:
        """Main scanning function"""
        print(f"[*] Starting network scan of {network}")
        print(f"[*] Timestamp: {datetime.now()}")
        
        # Discovery phase
        live_hosts = self.ping_sweep(network)
        arp_results = self.arp_scan(network)
        
        # Combine results
        all_hosts = set(live_hosts)
        mac_map = dict(arp_results)
        all_hosts.update(mac_map.keys())
        
        print(f"[*] Found {len(all_hosts)} live hosts")
        
        # Scan each host
        for ip in all_hosts:
            print(f"\n[*] Scanning {ip}")
            
            result = ScanResult(ip=ip)
            result.hostname = self.resolve_hostname(ip)
            result.mac_address = mac_map.get(ip, "")
            result.os_fingerprint = self.os_fingerprint_ttl(ip)
            
            # Port scanning
            ports_to_scan = self.common_ports
            if self.config.get('scan_all_ports', False):
                ports_to_scan = list(range(1, 1025))
            
            if self.config.get('stealth_scan', True):
                result.open_ports = self.syn_scan(ip, ports_to_scan)
            else:
                result.open_ports = self.tcp_connect_scan(ip, ports_to_scan)
            
            # Service detection and vulnerability assessment
            for port in result.open_ports:
                banner = self.banner_grab(ip, port)
                result.services[port] = banner
                
                vulns = self.check_vulnerabilities(banner, port)
                result.vulnerabilities.extend(vulns)
            
            self.results.append(result)
            
            # Check for high-severity vulnerabilities
            high_severity_vulns = [v for v in result.vulnerabilities 
                                 if v.get('severity') == 'HIGH']
            if high_severity_vulns and self.config.get('notifications', False):
                self.send_alert(result, high_severity_vulns)
    
    def send_alert(self, result: ScanResult, vulnerabilities: List[Dict]):
        """Send alert for high-severity vulnerabilities"""
        message = f"HIGH SEVERITY VULNERABILITY DETECTED!\n"
        message += f"Host: {result.ip} ({result.hostname})\n"
        message += f"Vulnerabilities:\n"
        
        for vuln in vulnerabilities:
            message += f"- {vuln['cve']}: {vuln['description']} (Score: {vuln['score']})\n"
        
        # Discord webhook (if configured)
        if self.config.get('discord_webhook'):
            try:
                payload = {
                    "content": f"🚨 **SECURITY ALERT** 🚨\n```{message}```"
                }
                requests.post(self.config['discord_webhook'], json=payload)
                print(f"[+] Discord alert sent for {result.ip}")
            except Exception as e:
                print(f"[-] Failed to send Discord alert: {e}")
    
    def generate_report(self, format_type: str = 'table'):
        """Generate and display results"""
        if not self.results:
            print("[-] No results to display")
            return
        
        if format_type == 'table':
            self.display_table_report()
        elif format_type == 'html':
            self.generate_html_report()
        elif format_type == 'markdown':
            self.generate_markdown_report()
        elif format_type == 'json':
            self.generate_json_report()
    
    def display_table_report(self):
        """Display results in CLI table format"""
        if not TABULATE_AVAILABLE:
            # Fallback to simple text display
            for result in self.results:
                print(f"\nHost: {result.ip}")
                print(f"  Hostname: {result.hostname}")
                print(f"  OS: {result.os_fingerprint}")
                print(f"  MAC: {result.mac_address}")
                print(f"  Open Ports: {', '.join(map(str, result.open_ports))}")
                if result.vulnerabilities:
                    print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
            return
        
        # Summary table
        table_data = []
        for result in self.results:
            vuln_count = len(result.vulnerabilities)
            high_vulns = len([v for v in result.vulnerabilities if v.get('severity') == 'HIGH'])
            
            table_data.append([
                result.ip,
                result.hostname,
                result.os_fingerprint,
                len(result.open_ports),
                vuln_count,
                high_vulns
            ])
        
        headers = ['IP', 'Hostname', 'OS', 'Open Ports', 'Vulnerabilities', 'High Risk']
        print("\n" + "="*80)
        print("NETWORK SCAN SUMMARY")
        print("="*80)
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        
        # Detailed results
        for result in self.results:
            if result.open_ports:
                print(f"\nDetailed results for {result.ip}:")
                service_data = []
                for port in result.open_ports:
                    service = result.services.get(port, "Unknown")[:50]
                    vulns = [v for v in result.vulnerabilities if str(port) in str(v)]
                    vuln_info = f"{len(vulns)} found" if vulns else "None"
                    service_data.append([port, service, vuln_info])
                
                print(tabulate(service_data, 
                             headers=['Port', 'Service', 'Vulnerabilities'], 
                             tablefmt='simple'))
    
    def generate_html_report(self):
        """Generate HTML report"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetRecon Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; }
                .summary { background-color: #ecf0f1; padding: 15px; margin: 10px 0; }
                .host { border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; }
                .vulnerability { background-color: #e74c3c; color: white; padding: 5px; margin: 5px 0; }
                .service { background-color: #3498db; color: white; padding: 5px; margin: 5px 0; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NetRecon Security Report</h1>
                <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            </div>
        """
        
        # Summary
        total_hosts = len(self.results)
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        high_vulns = sum(len([v for v in r.vulnerabilities if v.get('severity') == 'HIGH']) 
                        for r in self.results)
        
        html_content += f"""
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Total Hosts Scanned:</strong> {total_hosts}</p>
                <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
                <p><strong>High Risk Vulnerabilities:</strong> {high_vulns}</p>
            </div>
        """
        
        # Host details
        for result in self.results:
            html_content += f"""
            <div class="host">
                <h3>Host: {result.ip}</h3>
                <p><strong>Hostname:</strong> {result.hostname}</p>
                <p><strong>OS Fingerprint:</strong> {result.os_fingerprint}</p>
                <p><strong>MAC Address:</strong> {result.mac_address}</p>
                <p><strong>Open Ports:</strong> {', '.join(map(str, result.open_ports))}</p>
            """
            
            if result.vulnerabilities:
                html_content += "<h4>Vulnerabilities:</h4>"
                for vuln in result.vulnerabilities:
                    html_content += f"""
                    <div class="vulnerability">
                        <strong>{vuln['cve']}</strong> - {vuln['description']} 
                        (Severity: {vuln['severity']}, Score: {vuln['score']})
                    </div>
                    """
            
            html_content += "</div>"
        
        html_content += "</body></html>"
        
        # Write to file
        filename = f"netrecon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to: {filename}")
    
    def generate_markdown_report(self):
        """Generate Markdown report"""
        md_content = f"# NetRecon Security Report\n\n"
        md_content += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Summary
        total_hosts = len(self.results)
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        high_vulns = sum(len([v for v in r.vulnerabilities if v.get('severity') == 'HIGH']) 
                        for r in self.results)
        
        md_content += f"## Scan Summary\n\n"
        md_content += f"- **Total Hosts Scanned:** {total_hosts}\n"
        md_content += f"- **Total Vulnerabilities:** {total_vulns}\n" 
        md_content += f"- **High Risk Vulnerabilities:** {high_vulns}\n\n"
        
        # Detailed results
        md_content += f"## Detailed Results\n\n"
        
        for result in self.results:
            md_content += f"### Host: {result.ip}\n\n"
            md_content += f"- **Hostname:** {result.hostname}\n"
            md_content += f"- **OS Fingerprint:** {result.os_fingerprint}\n"
            md_content += f"- **MAC Address:** {result.mac_address}\n"
            md_content += f"- **Open Ports:** {', '.join(map(str, result.open_ports))}\n\n"
            
            if result.services:
                md_content += f"#### Services\n\n"
                for port, service in result.services.items():
                    md_content += f"- **Port {port}:** {service[:100]}...\n"
                md_content += "\n"
            
            if result.vulnerabilities:
                md_content += f"#### Vulnerabilities\n\n"
                for vuln in result.vulnerabilities:
                    md_content += f"- **{vuln['cve']}** ({vuln['severity']}): {vuln['description']}\n"
                md_content += "\n"
        
        # Write to file
        filename = f"netrecon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, 'w') as f:
            f.write(md_content)
        
        print(f"[+] Markdown report saved to: {filename}")
    
    def generate_json_report(self):
        """Generate JSON report"""
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_hosts": len(self.results),
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in self.results)
            },
            "results": [asdict(result) for result in self.results]
        }
        
        filename = f"netrecon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[+] JSON report saved to: {filename}")


def load_config(config_file: str) -> Dict:
    """Load configuration from file"""
    default_config = {
        'stealth_scan': True,
        'randomize_ports': False,
        'scan_delay': 0,
        'spoof_mac': False,
        'scan_all_ports': False,
        'notifications': False,
        'discord_webhook': None
    }
    
    if Path(config_file).exists():
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            default_config.update(user_config)
        except Exception as e:
            print(f"[-] Error loading config: {e}")
    
    return default_config


def create_sample_config():
    """Create a sample configuration file"""
    sample_config = {
        "stealth_scan": True,
        "randomize_ports": True,
        "scan_delay": 0.1,
        "spoof_mac": False,
        "scan_all_ports": False,
        "notifications": False,
        "discord_webhook": "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
    }
    
    with open("netrecon_config.json", 'w') as f:
        json.dump(sample_config, f, indent=2)
    
    print("[+] Sample configuration file created: netrecon_config.json")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="NetRecon - Advanced Network Security Scanner",
        epilog="Example: python netrecon.py -n 192.168.1.0/24 -o html"
    )
    
    parser.add_argument('-n', '--network',
                       help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-c', '--config', default='netrecon_config.json',
                       help='Configuration file path')
    parser.add_argument('-o', '--output', choices=['table', 'html', 'markdown', 'json'],
                       default='table', help='Output format')
    parser.add_argument('--create-config', action='store_true',
                       help='Create sample configuration file')
    parser.add_argument('--stealth', action='store_true',
                       help='Enable stealth scanning')
    parser.add_argument('--all-ports', action='store_true',
                       help='Scan all ports (1-1024)')
    
    args = parser.parse_args()
    
    # Create sample config if requested
    if args.create_config:
        create_sample_config()
        return
    
    # Check if network is provided when not creating config
    if not args.network:
        parser.error("the following arguments are required: -n/--network")
    
    # Check for required dependencies
    if not SCAPY_AVAILABLE:
        print("[!] Warning: Scapy not installed. Some features will be limited.")
        print("    Install with: pip install scapy")
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    if args.stealth:
        config['stealth_scan'] = True
    if args.all_ports:
        config['scan_all_ports'] = True
    
    # Validate network
    try:
        ipaddress.IPv4Network(args.network, strict=False)
    except ValueError:
        print(f"[-] Invalid network format: {args.network}")
        sys.exit(1)
    
    # Security check - require root for raw sockets
    if config.get('stealth_scan', True) and SCAPY_AVAILABLE:
        try:
            import os
            if os.geteuid() != 0:
                print("[!] Warning: Stealth scanning requires root privileges")
                print("    Run with sudo or disable stealth scanning")
        except AttributeError:
            # Windows doesn't have geteuid
            pass
    
    print("\n" + "="*60)
    print("NetRecon - Advanced Network Security Scanner")
    print("="*60)
    print(f"Target Network: {args.network}")
    print(f"Stealth Mode: {'Enabled' if config['stealth_scan'] else 'Disabled'}")
    print(f"Output Format: {args.output}")
    print("="*60)
    
    # Legal disclaimer
    print("\n[!] LEGAL DISCLAIMER:")
    print("    This tool is for authorized security testing only.")
    print("    Ensure you have permission to scan the target network.")
    print("    Unauthorized scanning may violate local laws.")
    
    # Confirmation prompt
    try:
        confirm = input("\n[?] Continue with scan? (y/N): ")
        if confirm.lower() != 'y':
            print("[*] Scan cancelled by user")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n[*] Scan cancelled by user")
        sys.exit(0)
    
    # Initialize and run scanner
    scanner = NetworkScanner(config)
    
    try:
        # Perform scan
        start_time = time.time()
        scanner.scan_network(args.network)
        end_time = time.time()
        
        print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[*] Found {len(scanner.results)} hosts")
        
        # Generate report
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        if scanner.results:
            print("[*] Generating partial results...")
            scanner.generate_report(args.output)
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()