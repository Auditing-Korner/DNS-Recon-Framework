#!/usr/bin/env python3

import socket
import argparse
import time
import random
import csv
import ipaddress
import textwrap
import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Handle imports for framework integration
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# ANSI escape codes for colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def colored_message(message, color):
    return f"{color}{message}{RESET}"

def is_valid_ip(ip):
    """Checks if a given string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_domain(domain, dns_server, timeout=2, query_type=socket.SOCK_DGRAM):
    """Attempts to resolve a domain using a specified DNS server."""
    try:
        with socket.socket(socket.AF_INET, query_type) as resolver:
            resolver.settimeout(timeout)
            query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            for part in domain.encode('utf-8').split(b'.'):
                query += bytes([len(part)]) + part
            query += b'\x00\x00\x01\x00\x01'
            resolver.connect((dns_server, 53))
            resolver.sendall(query)
            data = resolver.recv(1024)
            if data:
                parts = data.split(b'\xc0\x0c')
                if len(parts) > 1:
                    ip_part = parts[1][5:9]
                    return ".".join(map(str, ip_part))
            return None
    except socket.timeout:
        return "Timeout"
    except ConnectionRefusedError:
        return "Connection Refused"
    except OSError as e:
        return f"OS Error: {e}"
    except Exception as e:
        return f"Error: {e}"

class DNSServerFinder(BaseTool):
    """Tool to find and test DNS servers for a domain"""
    
    def __init__(self):
        super().__init__(
            name="find-server",
            description="Discover and test DNS servers"
        )
        self.domain = None
        self.server = None
        self.timeout = 2
        self.shuffle = False
        self.use_tcp = False
        self.test_top = False
        self.test_nl = False
        self.test_eg = False
        self.test_vodafone = False
        self.test_root = False
        self.test_aws = False
        self.test_all = False
        self.list_file = None
        self.results = {}
        
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        super().setup_argparse(parser)
        
        parser.add_argument("domain", help="The domain name to resolve (e.g., google.com)")
        parser.add_argument("-s", "--server", help="The IP address of a specific DNS server to test.")
        parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout in seconds for the DNS query (default: 2)")
        parser.add_argument("--top", action="store_true", help="Test against top public DNS servers.")
        parser.add_argument("--nl", "--holland", action="store_true", help="Test against Netherlands DNS servers.")
        parser.add_argument("--eg", "--egypt", action="store_true", help="Test against Egypt DNS servers.")
        parser.add_argument("--vodafone", action="store_true", help="Test against Vodafone DNS servers.")
        parser.add_argument("--all", action="store_true", help="Test against all known DNS servers.")
        parser.add_argument("--list", type=str, help="Path to a CSV file with DNS server IPs.")
        parser.add_argument("--shuffle", action="store_true", help="Shuffle DNS servers before testing.")
        parser.add_argument("--root", action="store_true", help="Test against root DNS servers.")
        parser.add_argument("--aws", action="store_true", help="Test against AWS DNS servers.")
        parser.add_argument("--tcp", action="store_true", help="Use TCP instead of UDP for queries.")

    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if required dependencies are available"""
        # No external dependencies needed
        return True, None
        
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
        # Store arguments
        self.domain = args.domain
        self.server = args.server
        self.timeout = args.timeout
        self.test_top = args.top
        self.test_nl = args.nl
        self.test_eg = args.eg
        self.test_vodafone = args.vodafone
        self.test_all = args.all
        self.test_root = args.root
        self.test_aws = args.aws
        self.list_file = args.list
        self.shuffle = args.shuffle
        self.use_tcp = args.tcp
        
        # Print banner if not in framework mode
        if not self.framework_mode:
            self._print_banner()
        else:
            self.logger.info("DNS Server Finder started")
            
        # DNS server lists
        dns_lists = {
            "top": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "77.88.8.8", "77.88.8.1", "95.85.95.85", "2.56.220.2", "185.222.222.222", "45.11.45.11", "193.110.81.0", "185.253.5.0", "101.101.101.101", "101.102.103.104", "114.114.114.114", "114.114.115.115"],
            "nl": ["80.80.81.81", "80.80.80.80", "194.61.59.25", "87.213.100.113", "46.166.189.67", "80.113.19.90", "213.125.136.58", "51.158.152.202", "89.146.35.15", "145.131.193.46", "91.229.62.10", "84.28.145.175", "20.86.159.155", "91.220.37.68", "77.250.123.113", "84.31.128.12", "79.137.195.32", "89.188.18.103", "188.120.47.97", "88.221.162.222", "88.221.162.147", "85.203.37.225", "88.221.163.76", "78.140.167.63", "217.171.225.98", "88.221.163.147", "94.168.100.234", "88.221.162.27", "89.106.206.45", "95.211.209.150", "95.179.159.117", "185.183.32.48", "89.255.26.18", "84.38.234.244", "81.173.126.239", "95.211.160.51", "84.243.224.236", "84.26.74.61"],
            "eg": ["217.139.208.19", "45.246.200.158", "82.129.253.33", "41.155.240.28", "41.129.105.228", "156.200.99.53", "41.39.73.110", "41.41.152.225", "41.38.89.26", "197.44.197.4", "45.240.56.69", "41.32.78.185", "41.32.15.27", "84.205.101.37", "197.44.43.24", "197.45.137.161", "193.227.29.241", "81.21.104.102", "193.227.60.75", "41.32.39.199", "154.236.176.28", "154.181.65.91", "156.200.123.58", "156.200.100.83", "41.155.246.167", "84.36.35.199", "45.240.35.147", "156.195.31.48", "196.218.20.186", "156.212.177.192", "196.219.185.186", "196.201.242.99", "41.64.175.172", "41.233.93.98", "41.155.202.84", "197.246.186.141", "81.10.12.114", "41.155.212.104", "154.180.51.54", "217.139.116.22", "154.239.9.81", "41.234.183.53", "41.39.242.34", "156.195.121.231", "41.176.155.21", "41.65.234.152", "41.129.22.158"],
            "vodafone": ["90.255.255.90", "90.255.255.255", "203.97.78.43", "203.97.78.44", "203.109.191.1", "203.118.191.1", "89.19.64.164", "89.19.64.36", "141.1.1.1"],
            "root": ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"],
            "aws": ["205.251.192.0", "205.251.193.0", "205.251.194.0", "205.251.195.0", "205.251.196.0", "205.251.197.0", "205.251.198.0", "205.251.199.0", "169.254.169.253"]
        }
        all_dns_servers = sorted(list(set(sum(dns_lists.values(), []))))

        # Create result
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": self.domain,
                "scan_date": datetime.now().isoformat(),
                "results": {}
            }
        )
        
        # Run the appropriate scan
        if self.server:
            # Test a single server
            self.results = self._test_dns_servers([self.server])
            
        elif self.list_file:
            # Test servers from a file
            if servers := self._load_dns_servers_from_csv(self.list_file):
                self.results = self._test_dns_servers(servers)
                
        elif any([self.test_top, self.test_nl, self.test_eg, self.test_vodafone, self.test_root, self.test_aws, self.test_all]):
            # Test selected DNS server lists
            servers = []
            if self.test_top or self.test_all:
                servers.extend(dns_lists["top"])
            if self.test_nl or self.test_all:
                servers.extend(dns_lists["nl"])
            if self.test_eg or self.test_all:
                servers.extend(dns_lists["eg"])
            if self.test_vodafone or self.test_all:
                servers.extend(dns_lists["vodafone"])
            if self.test_root or self.test_all:
                servers.extend(dns_lists["root"])
            if self.test_aws or self.test_all:
                servers.extend(dns_lists["aws"])
                
            # Remove duplicates
            servers = list(set(servers))
            self.results = self._test_dns_servers(servers)
            
        else:
            # If no specific test was selected, just test top DNS servers
            self.results = self._test_dns_servers(dns_lists["top"])
        
        # Add results to metadata
        result.metadata["results"] = self.results
        
        # Add findings based on results
        self._add_findings_to_result(result)
        
        return result
    
    def _print_banner(self):
        """Print banner for standalone mode"""
        banner = textwrap.dedent(f"""
        {CYAN}===================================================={RESET}
        {CYAN} DNS Resolution Tester - rfs85 {RESET}
        {CYAN}===================================================={RESET}
        This script tests DNS resolution for a given domain against
        specified or lists of DNS servers, including root and AWS servers.
        It provides detailed output with colored messages for easy analysis.
        """)
        print(banner)
    
    def _load_dns_servers_from_csv(self, filename: str) -> List[str]:
        """Loads DNS server IPs from a CSV file, with validation"""
        try:
            with open(filename, 'r') as csvfile:
                servers = [ip.strip() for row in csv.reader(csvfile) if row and is_valid_ip((ip := row[0].strip()))]
            
            if self.framework_mode:
                self.logger.info(f"Loaded {len(servers)} DNS servers from {filename}")
            else:
                print(f"Loaded {len(servers)} DNS servers from {filename}")
                
            return servers
        except FileNotFoundError:
            message = f"Error: CSV file '{filename}' not found."
            if self.framework_mode:
                self.logger.error(message)
            else:
                print(colored_message(message, RED))
            return []
        except Exception as e:
            message = f"Error reading CSV file '{filename}': {e}"
            if self.framework_mode:
                self.logger.error(message)
            else:
                print(colored_message(message, RED))
            return []
    
    def _test_dns_servers(self, dns_servers: List[str]) -> Dict[str, str]:
        """Tests DNS resolution for a domain against a list of DNS servers"""
        results = {}
        
        if self.shuffle:
            random.shuffle(dns_servers)
            
        query_type = socket.SOCK_STREAM if self.use_tcp else socket.SOCK_DGRAM
        protocol = "TCP" if self.use_tcp else "UDP"
        
        for server in dns_servers:
            if not is_valid_ip(server):
                message = f"Skipping invalid IP: {server}"
                if self.framework_mode:
                    self.logger.warning(message)
                else:
                    print(colored_message(message, YELLOW))
                results[server] = "Invalid IP"
                continue
                
            if self.framework_mode:
                self.logger.info(f"Testing {self.domain} against {server} ({protocol})...")
            else:
                print(f"Testing {self.domain} against {server} ({protocol})...", end='', flush=True)
                
            start_time = time.time()
            result = resolve_domain(self.domain, server, self.timeout, query_type)
            elapsed_time = time.time() - start_time
            
            if result and not result.startswith(("Timeout", "Connection Refused", "OS Error", "Error")):
                message = f"Resolved: {result} ({elapsed_time:.3f}s)"
                if self.framework_mode:
                    self.logger.info(message)
                else:
                    print(colored_message(message, GREEN))
                results[server] = result
            elif result:
                message = f"{result} ({elapsed_time:.3f}s)"
                if self.framework_mode:
                    self.logger.error(message)
                else:
                    print(colored_message(message, RED))
                results[server] = result
            else:
                message = f"Unknown Error ({elapsed_time:.3f}s)"
                if self.framework_mode:
                    self.logger.warning(message)
                else:
                    print(colored_message(message, YELLOW))
                results[server] = "Unknown"
                
        return results
    
    def _add_findings_to_result(self, result: ToolResult) -> None:
        """Add findings based on DNS server test results"""
        # Count successful resolvers
        successful = [server for server, response in self.results.items() 
                     if response and not response.startswith(("Timeout", "Connection Refused", "OS Error", "Error", "Unknown", "Invalid"))]
        
        if successful:
            result.add_finding(
                title=f"Domain {self.domain} is resolvable",
                description=f"Domain successfully resolved by {len(successful)} DNS servers",
                risk_level="Info",
                evidence=f"First resolver: {successful[0]} -> {self.results[successful[0]]}"
            )
        else:
            result.add_finding(
                title=f"Domain {self.domain} resolution failed",
                description=f"Domain could not be resolved by any of the {len(self.results)} DNS servers tested",
                risk_level="Medium",
                evidence="All DNS servers failed to resolve the domain"
            )
            
        # Check for inconsistent resolutions
        ip_addresses = {}
        for server, response in self.results.items():
            if response and not response.startswith(("Timeout", "Connection Refused", "OS Error", "Error", "Unknown", "Invalid")):
                if response not in ip_addresses:
                    ip_addresses[response] = []
                ip_addresses[response].append(server)
                
        if len(ip_addresses) > 1:
            result.add_finding(
                title="Inconsistent DNS resolution",
                description=f"Domain resolves to different IPs depending on the DNS server used",
                risk_level="Medium",
                evidence=f"Found {len(ip_addresses)} different IP addresses: {', '.join(ip_addresses.keys())}"
            )

def main():
    tool = DNSServerFinder()
    return tool.main()

if __name__ == "__main__":
    main()
