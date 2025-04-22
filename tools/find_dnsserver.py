#!/usr/bin/env python3
"""
DNS Server Discovery Tool

Discovers and tests DNS servers:
- Find authoritative nameservers
- Test recursive resolvers
- Check for common misconfigurations
- Analyze response times and reliability
"""

import argparse
import dns.resolver
import dns.query
import dns.name
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

try:
    from .framework_tool_template import FrameworkTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.framework_tool_template import FrameworkTool, ToolResult

class DNSServerFinder(FrameworkTool):
    """DNS Server Discovery and Testing Tool"""
    
    def __init__(self):
        super().__init__(
            name="dns-server-finder",
            description="DNS Server Discovery and Testing Tool"
        )
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def setup_tool_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Set up tool-specific arguments"""
        parser.add_argument('domain', help='Target domain to analyze')
        parser.add_argument('-s', '--server', help='Specific DNS server to test')
        parser.add_argument('-t', '--timeout', type=int, default=5,
                          help='Query timeout in seconds')
        parser.add_argument('--top', action='store_true',
                          help='Test top public DNS servers')
        parser.add_argument('--nl', action='store_true',
                          help='Test Netherlands DNS servers')
        parser.add_argument('--eg', action='store_true',
                          help='Test Egypt DNS servers')
        parser.add_argument('--vodafone', action='store_true',
                          help='Test Vodafone DNS servers')
        parser.add_argument('--all', action='store_true',
                          help='Test all known DNS servers')
        parser.add_argument('--list', type=str,
                          help='File containing list of DNS servers to test')
        parser.add_argument('--shuffle', action='store_true',
                          help='Randomize server testing order')
        parser.add_argument('--root', action='store_true',
                          help='Test root DNS servers')
        parser.add_argument('--aws', action='store_true',
                          help='Test AWS DNS servers')
        parser.add_argument('--tcp', action='store_true',
                          help='Use TCP instead of UDP for queries')
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        """Execute DNS server discovery and testing"""
        try:
            # Update metadata
            result.metadata.update({
                "domain": args.domain,
                "timeout": args.timeout,
                "use_tcp": args.tcp
            })
            
            # Find authoritative nameservers
            try:
                ns_records = dns.resolver.resolve(args.domain, 'NS')
                nameservers = [str(ns.target).rstrip('.') for ns in ns_records]
                result.metadata["nameservers"] = nameservers
                
                for ns in nameservers:
                    self._test_nameserver(ns, args, result)
            except Exception as e:
                result.add_error(f"Error finding nameservers: {str(e)}")
            
            # Test specified server if provided
            if args.server:
                self._test_nameserver(args.server, args, result)
            
            # Test predefined server lists based on flags
            if args.top:
                self._test_server_list(self.TOP_SERVERS, "Top Public DNS Servers", args, result)
            if args.nl:
                self._test_server_list(self.NL_SERVERS, "Netherlands DNS Servers", args, result)
            if args.eg:
                self._test_server_list(self.EG_SERVERS, "Egypt DNS Servers", args, result)
            if args.vodafone:
                self._test_server_list(self.VODAFONE_SERVERS, "Vodafone DNS Servers", args, result)
            if args.aws:
                self._test_server_list(self.AWS_SERVERS, "AWS DNS Servers", args, result)
            if args.root:
                self._test_server_list(self.ROOT_SERVERS, "Root DNS Servers", args, result)
            
            # Test servers from file if specified
            if args.list:
                try:
                    with open(args.list) as f:
                        servers = [line.strip() for line in f if line.strip()]
                        self._test_server_list(servers, f"Servers from {args.list}", args, result)
                except Exception as e:
                    result.add_error(f"Error reading server list file: {str(e)}")
            
        except Exception as e:
            result.add_error(f"Error during execution: {str(e)}")
    
    def _test_nameserver(self, server: str, args: argparse.Namespace, result: ToolResult) -> None:
        """Test a single nameserver"""
        try:
            # Basic connectivity test
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = args.timeout
            resolver.lifetime = args.timeout
            
            start_time = datetime.now()
            try:
                answers = resolver.resolve(args.domain, 'A')
                response_time = (datetime.now() - start_time).total_seconds()
                
                result.add_finding(
                    title=f"Nameserver Responding: {server}",
                    description=f"Successfully queried {args.domain}",
                    risk_level="Info",
                    evidence=f"Response time: {response_time:.3f}s, Records: {[str(r) for r in answers]}"
                )
            except Exception as e:
                result.add_finding(
                    title=f"Nameserver Error: {server}",
                    description=f"Failed to query {args.domain}",
                    risk_level="High",
                    evidence=str(e)
                )
            
            # Check for recursive queries
            try:
                test_domain = "example.com."
                resolver.resolve(test_domain, 'A')
                result.add_finding(
                    title=f"Open Recursive Resolver: {server}",
                    description="Server allows recursive queries",
                    risk_level="Medium",
                    evidence=f"Successfully resolved {test_domain}"
                )
            except:
                pass
            
        except Exception as e:
            result.add_finding(
                title=f"Nameserver Test Failed: {server}",
                description="Could not complete nameserver tests",
                risk_level="High",
                evidence=str(e)
            )
    
    def _test_server_list(self, servers: List[str], list_name: str, args: argparse.Namespace, result: ToolResult) -> None:
        """Test a list of DNS servers"""
        result.add_finding(
            title=f"Testing {list_name}",
            description=f"Starting tests for {len(servers)} servers",
            risk_level="Info"
        )
        
        for server in servers:
            self._test_nameserver(server, args, result)
    
    # Predefined server lists
    TOP_SERVERS = [
        "8.8.8.8",  # Google
        "1.1.1.1",  # Cloudflare
        "9.9.9.9",  # Quad9
        "208.67.222.222"  # OpenDNS
    ]
    
    NL_SERVERS = [
        "194.109.6.66",  # xs4all
        "194.109.9.99"
    ]
    
    EG_SERVERS = [
        "163.121.128.134",
        "163.121.128.135"
    ]
    
    VODAFONE_SERVERS = [
        "194.224.0.2",
        "194.224.0.1"
    ]
    
    AWS_SERVERS = [
        "205.251.192.0",
        "205.251.193.0",
        "205.251.194.0",
        "205.251.195.0"
    ]
    
    ROOT_SERVERS = [
        "198.41.0.4",    # a.root-servers.net
        "199.9.14.201",  # b.root-servers.net
        "192.33.4.12",   # c.root-servers.net
        "199.7.91.13",   # d.root-servers.net
        "192.203.230.10" # e.root-servers.net
    ]

def main():
    tool = DNSServerFinder()
    return tool.main()

if __name__ == "__main__":
    sys.exit(0 if main()['status'] == 'success' else 1)
