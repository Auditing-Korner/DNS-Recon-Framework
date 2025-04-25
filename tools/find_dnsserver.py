#!/usr/bin/env python3
"""
DNS Server Discovery Tool

Discovers and tests DNS servers:
- Find authoritative nameservers
- Test recursive resolvers
- Check for common misconfigurations
- Analyze response times and reliability
"""

import dns.resolver
import dns.query
import dns.name
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from .base_tool import BaseTool, ToolResult

class DNSServerFinder(BaseTool):
    """DNS Server Discovery and Testing Tool"""
    
    def __init__(self):
        super().__init__(
            name="find_server",
            description="DNS Server Discovery and Analysis Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run DNS server discovery with provided arguments"""
        domain = self.get_param('domain')
        server_types = self.get_param('server_types', 'all').split(',')
        timeout = self.get_param('timeout', 5)
        
        # Configure resolver
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        if self.get_param('nameserver'):
            self.resolver.nameservers = [self.get_param('nameserver')]
            
        try:
            # Find nameservers
            try:
                ns_records = self.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    result.add_finding({
                        'title': 'Found Nameserver',
                        'description': f'Discovered nameserver for {domain}',
                        'risk_level': 'Info',
                        'details': {
                            'nameserver': str(ns.target).rstrip('.'),
                            'type': 'Authoritative'
                        }
                    })
                    
                    # Get IP addresses for nameservers
                    try:
                        ns_hostname = str(ns.target).rstrip('.')
                        answers = self.resolver.resolve(ns_hostname, 'A')
                        for answer in answers:
                            result.add_finding({
                                'title': 'Nameserver IP',
                                'description': f'Resolved IP address for nameserver {ns_hostname}',
                                'risk_level': 'Info',
                                'details': {
                                    'nameserver': ns_hostname,
                                    'ip_address': str(answer),
                                    'type': 'Authoritative'
                                }
                            })
                    except Exception as e:
                        result.add_warning(f"Could not resolve IP for nameserver {ns_hostname}: {str(e)}")
                        
            except dns.resolver.NXDOMAIN:
                result.add_error(f"Domain {domain} does not exist")
            except dns.resolver.NoAnswer:
                result.add_warning(f"No NS records found for {domain}")
            except Exception as e:
                result.add_error(f"Error querying NS records: {str(e)}")
                
            # Check for recursive resolvers if requested
            if 'recursive' in server_types or 'all' in server_types:
                self._check_recursive_resolvers(result)
                
        except Exception as e:
            result.add_error(f"Error during server discovery: {str(e)}")
            if self.get_param('verbose', False):
                import traceback
                result.add_error(traceback.format_exc())
    
    def _check_recursive_resolvers(self, result: ToolResult) -> None:
        """Check for recursive DNS resolvers"""
        common_resolvers = [
            '8.8.8.8',  # Google
            '1.1.1.1',  # Cloudflare
            '9.9.9.9',  # Quad9
            '208.67.222.222'  # OpenDNS
        ]
        
        for resolver_ip in common_resolvers:
            try:
                test_resolver = dns.resolver.Resolver()
                test_resolver.nameservers = [resolver_ip]
                test_resolver.timeout = 2
                
                # Try to resolve a known domain
                try:
                    answers = test_resolver.resolve('www.google.com', 'A')
                    result.add_finding({
                        'title': 'Working Recursive Resolver',
                        'description': f'Found working recursive DNS resolver',
                        'risk_level': 'Info',
                        'details': {
                            'ip_address': resolver_ip,
                            'type': 'Recursive',
                            'provider': self._get_resolver_provider(resolver_ip)
                        }
                    })
                except:
                    continue
                    
            except Exception as e:
                result.add_warning(f"Error checking resolver {resolver_ip}: {str(e)}")
                
    def _get_resolver_provider(self, ip: str) -> str:
        """Get the provider name for a known resolver IP"""
        providers = {
            '8.8.8.8': 'Google DNS',
            '8.8.4.4': 'Google DNS',
            '1.1.1.1': 'Cloudflare DNS',
            '1.0.0.1': 'Cloudflare DNS',
            '9.9.9.9': 'Quad9',
            '149.112.112.112': 'Quad9',
            '208.67.222.222': 'OpenDNS',
            '208.67.220.220': 'OpenDNS'
        }
        return providers.get(ip, 'Unknown')

def main():
    """Entry point for DNS server finder tool"""
    tool = DNSServerFinder()
    return tool.main()

if __name__ == "__main__":
    main()
