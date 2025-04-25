#!/usr/bin/env python3
"""
Domain Seizure Detection Tool

Detects potential law enforcement domain seizures:
- WHOIS record changes
- DNS record modifications
- Seizure notice pages
- Redirection patterns
- Historical data analysis
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import whois
import requests
import sys
import os
import json
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class SeizureDetector(BaseTool):
    """Domain Seizure Detection Tool"""
    
    def __init__(self):
        super().__init__(
            name="seizure",
            description="Domain Seizure Detection Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize seizure indicators
        self.indicators = {
            'whois': {
                'registrant_patterns': [
                    'seized',
                    'forfeited',
                    'law enforcement',
                    'government',
                    'police',
                    'investigation'
                ],
                'nameserver_patterns': [
                    'seized',
                    'blocked',
                    'forfeited'
                ]
            },
            'dns': {
                'ip_ranges': [
                    '127.0.0.1',  # Localhost
                    '0.0.0.0'     # Null route
                ],
                'cname_patterns': [
                    'seized',
                    'blocked',
                    'forfeited'
                ]
            },
            'http': {
                'title_patterns': [
                    'seized',
                    'forfeited',
                    'blocked',
                    'notice'
                ],
                'body_patterns': [
                    'law enforcement',
                    'seized by',
                    'forfeited',
                    'criminal investigation',
                    'court order'
                ],
                'status_codes': [
                    451,  # Unavailable for legal reasons
                    403   # Forbidden
                ]
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run seizure detection with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_whois = self.get_param('check_whois', True)
        check_dns = self.get_param('check_dns', True)
        check_http = self.get_param('check_http', True)
        max_threads = int(self.get_param('threads', 10))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Run checks in parallel
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                if check_whois:
                    futures.append(executor.submit(
                        self._check_whois,
                        domain,
                        result
                    ))
                if check_dns:
                    futures.append(executor.submit(
                        self._check_dns,
                        domain,
                        result
                    ))
                if check_http:
                    futures.append(executor.submit(
                        self._check_http,
                        domain,
                        result
                    ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in seizure check: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during seizure detection: {str(e)}")

    def _check_whois(self, domain: str, result: ToolResult) -> None:
        """Check WHOIS records for seizure indicators"""
        try:
            w = whois.whois(domain)
            if w.domain_name:
                # Check registrant information
                registrant_text = ' '.join([
                    str(w.registrant_name or ''),
                    str(w.registrant_organization or ''),
                    str(w.registrant_country or '')
                ]).lower()
                
                for pattern in self.indicators['whois']['registrant_patterns']:
                    if pattern in registrant_text:
                        result.add_finding({
                            'title': "Suspicious Registrant Information",
                            'description': "WHOIS registrant data suggests possible seizure",
                            'risk_level': "High",
                            'details': {
                                'domain': domain,
                                'registrant_name': w.registrant_name,
                                'registrant_org': w.registrant_organization,
                                'registrant_country': w.registrant_country,
                                'matched_pattern': pattern
                            },
                            'recommendations': [
                                'Verify domain ownership',
                                'Check legal notices',
                                'Review domain history'
                            ]
                        })
                
                # Check nameservers
                if w.name_servers:
                    nameservers = [ns.lower() for ns in w.name_servers]
                    for pattern in self.indicators['whois']['nameserver_patterns']:
                        for ns in nameservers:
                            if pattern in ns:
                                result.add_finding({
                                    'title': "Suspicious Nameservers",
                                    'description': "WHOIS nameserver data suggests possible seizure",
                                    'risk_level': "High",
                                    'details': {
                                        'domain': domain,
                                        'nameservers': nameservers,
                                        'matched_pattern': pattern
                                    },
                                    'recommendations': [
                                        'Verify nameserver configuration',
                                        'Check DNS resolution',
                                        'Review domain status'
                                    ]
                                })
                                break
                
        except Exception as e:
            result.add_warning(f"Error checking WHOIS for {domain}: {str(e)}")

    def _check_dns(self, domain: str, result: ToolResult) -> None:
        """Check DNS records for seizure indicators"""
        try:
            # Check A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                for rr in a_records:
                    ip = str(rr)
                    for ip_range in self.indicators['dns']['ip_ranges']:
                        if ip.startswith(ip_range):
                            result.add_finding({
                                'title': "Suspicious IP Address",
                                'description': "Domain resolves to suspicious IP range",
                                'risk_level': "High",
                                'details': {
                                    'domain': domain,
                                    'ip_address': ip,
                                    'suspicious_range': ip_range
                                },
                                'recommendations': [
                                    'Verify DNS resolution',
                                    'Check domain status',
                                    'Review IP assignment'
                                ]
                            })
            except:
                pass
            
            # Check CNAME records
            try:
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                for rr in cname_records:
                    target = str(rr.target).rstrip('.')
                    for pattern in self.indicators['dns']['cname_patterns']:
                        if pattern in target.lower():
                            result.add_finding({
                                'title': "Suspicious CNAME Record",
                                'description': "Domain has suspicious CNAME target",
                                'risk_level': "High",
                                'details': {
                                    'domain': domain,
                                    'cname_target': target,
                                    'matched_pattern': pattern
                                },
                                'recommendations': [
                                    'Verify CNAME configuration',
                                    'Check domain redirection',
                                    'Review DNS records'
                                ]
                            })
            except:
                pass
                
        except Exception as e:
            result.add_warning(f"Error checking DNS for {domain}: {str(e)}")

    def _check_http(self, domain: str, result: ToolResult) -> None:
        """Check HTTP response for seizure indicators"""
        try:
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(
                        f"{protocol}://{domain}",
                        timeout=self.resolver.timeout,
                        allow_redirects=True
                    )
                    
                    # Check status code
                    if response.status_code in self.indicators['http']['status_codes']:
                        result.add_finding({
                            'title': "Legal Block Status Code",
                            'description': f"Domain returns {response.status_code} status code",
                            'risk_level': "High",
                            'details': {
                                'domain': domain,
                                'protocol': protocol,
                                'status_code': response.status_code,
                                'url': response.url
                            },
                            'recommendations': [
                                'Check legal notices',
                                'Verify domain status',
                                'Review HTTP response'
                            ]
                        })
                    
                    # Check page content
                    content = response.text.lower()
                    
                    # Check title
                    for pattern in self.indicators['http']['title_patterns']:
                        if f"<title>.*{pattern}.*</title>" in content:
                            result.add_finding({
                                'title': "Seizure Notice Title",
                                'description': "Page title suggests seizure notice",
                                'risk_level': "High",
                                'details': {
                                    'domain': domain,
                                    'protocol': protocol,
                                    'url': response.url,
                                    'matched_pattern': pattern
                                },
                                'recommendations': [
                                    'Review page content',
                                    'Check legal notices',
                                    'Verify domain status'
                                ]
                            })
                    
                    # Check body content
                    for pattern in self.indicators['http']['body_patterns']:
                        if pattern in content:
                            result.add_finding({
                                'title': "Seizure Notice Content",
                                'description': "Page content suggests seizure notice",
                                'risk_level': "High",
                                'details': {
                                    'domain': domain,
                                    'protocol': protocol,
                                    'url': response.url,
                                    'matched_pattern': pattern
                                },
                                'recommendations': [
                                    'Review page content',
                                    'Check legal notices',
                                    'Document findings'
                                ]
                            })
                    
                    break  # Stop after first successful connection
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error checking HTTP for {domain}: {str(e)}")

def main():
    """Entry point for seizure detector"""
    tool = SeizureDetector()
    return tool.main()

if __name__ == "__main__":
    main() 