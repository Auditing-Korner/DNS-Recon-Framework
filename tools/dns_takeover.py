#!/usr/bin/env python3
"""
DNS Takeover Detection Tool

Detects potential DNS takeover vulnerabilities:
- Dangling DNS records
- Unclaimed subdomains
- Expired domain registrations
- Misconfigured NS records
- Cloud service takeover risks
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import socket
import sys
import os
import json
import requests
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class DNSTakeoverDetector(BaseTool):
    """DNS Takeover Detection Tool"""
    
    def __init__(self):
        super().__init__(
            name="dns_takeover",
            description="DNS Takeover Detection Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize takeover signatures
        self.signatures = {
            'cloud_services': {
                'aws': {
                    'patterns': [
                        's3.amazonaws.com',
                        'elasticbeanstalk.com',
                        'cloudfront.net'
                    ],
                    'verification': {
                        'http_codes': [404, 403],
                        'body_patterns': [
                            'NoSuchBucket',
                            'NoSuchDistribution'
                        ]
                    }
                },
                'azure': {
                    'patterns': [
                        'azurewebsites.net',
                        'cloudapp.net',
                        'trafficmanager.net'
                    ],
                    'verification': {
                        'http_codes': [404],
                        'body_patterns': [
                            'This web app is stopped',
                            'not found'
                        ]
                    }
                },
                'gcp': {
                    'patterns': [
                        'appspot.com',
                        'googleapis.com',
                        'storage.googleapis.com'
                    ],
                    'verification': {
                        'http_codes': [404, 403],
                        'body_patterns': [
                            'The specified bucket does not exist'
                        ]
                    }
                }
            },
            'dns_patterns': {
                'dangling_cname': [
                    'NXDOMAIN',
                    'SERVFAIL'
                ],
                'dead_ns': [
                    'REFUSED',
                    'SERVFAIL'
                ]
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run DNS takeover detection with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_cloud = self.get_param('check_cloud', True)
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
            # Get subdomains first
            subdomains = self._enumerate_subdomains(domain, result)
            if not subdomains:
                result.add_warning("No subdomains found to check")
                return
            
            # Check for takeover vulnerabilities
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                # Submit tasks for each subdomain
                for subdomain in subdomains:
                    if check_dns:
                        futures.append(executor.submit(
                            self._check_dns_takeover, subdomain, result
                        ))
                    if check_cloud:
                        futures.append(executor.submit(
                            self._check_cloud_takeover, subdomain, result
                        ))
                    if check_http:
                        futures.append(executor.submit(
                            self._check_http_takeover, subdomain, result
                        ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in takeover check: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during takeover detection: {str(e)}")
            
    def _enumerate_subdomains(self, domain: str, result: ToolResult) -> Set[str]:
        """Enumerate subdomains using various methods"""
        subdomains = set()
        
        try:
            # Try zone transfer first
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    try:
                        xfr = dns.query.xfr(str(ns), domain)
                        zone = dns.zone.from_xfr(xfr)
                        for name, node in zone.nodes.items():
                            subdomain = str(name)
                            if subdomain != '@':
                                subdomains.add(f"{subdomain}.{domain}")
                    except:
                        continue
            except:
                pass
            
            # Try common record types
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if record_type == 'MX':
                            subdomains.add(str(rdata.exchange).rstrip('.'))
                        elif record_type == 'CNAME':
                            subdomains.add(str(rdata.target).rstrip('.'))
                        else:
                            subdomains.add(str(rdata))
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error enumerating subdomains: {str(e)}")
            
        return subdomains

    def _check_dns_takeover(self, subdomain: str, result: ToolResult) -> None:
        """Check for DNS-based takeover vulnerabilities"""
        try:
            # Check CNAME records
            try:
                cname_records = dns.resolver.resolve(subdomain, 'CNAME')
                for cname in cname_records:
                    target = str(cname.target).rstrip('.')
                    try:
                        dns.resolver.resolve(target, 'A')
                    except dns.resolver.NXDOMAIN:
                        result.add_finding({
                            'title': "Dangling CNAME Record",
                            'description': f"CNAME record points to non-existent domain",
                            'risk_level': "High",
                            'details': {
                                'subdomain': subdomain,
                                'cname_target': target
                            },
                            'recommendations': [
                                'Remove or update the dangling CNAME record',
                                'Verify ownership of target domain',
                                'Monitor domain expiration'
                            ]
                        })
            except dns.resolver.NoAnswer:
                pass
            
            # Check NS records
            try:
                ns_records = dns.resolver.resolve(subdomain, 'NS')
                for ns in ns_records:
                    ns_name = str(ns.target).rstrip('.')
                    try:
                        socket.gethostbyname(ns_name)
                    except socket.gaierror:
                        result.add_finding({
                            'title': "Dead Nameserver",
                            'description': f"Nameserver does not resolve to an IP",
                            'risk_level': "High",
                            'details': {
                                'subdomain': subdomain,
                                'nameserver': ns_name
                            },
                            'recommendations': [
                                'Remove or update the dead nameserver record',
                                'Verify nameserver configuration',
                                'Update DNS delegation'
                            ]
                        })
            except dns.resolver.NoAnswer:
                pass
                
        except Exception as e:
            result.add_warning(f"Error checking DNS takeover for {subdomain}: {str(e)}")

    def _check_cloud_takeover(self, subdomain: str, result: ToolResult) -> None:
        """Check for cloud service takeover vulnerabilities"""
        try:
            # Check CNAME and A records
            for record_type in ['CNAME', 'A']:
                try:
                    records = dns.resolver.resolve(subdomain, record_type)
                    for record in records:
                        target = str(record.target if record_type == 'CNAME' else record)
                        
                        # Check against cloud service patterns
                        for provider, config in self.signatures['cloud_services'].items():
                            for pattern in config['patterns']:
                                if pattern in target:
                                    # Verify takeover possibility
                                    if self._verify_cloud_takeover(target, config['verification']):
                                        result.add_finding({
                                            'title': f"Potential {provider.upper()} Service Takeover",
                                            'description': f"Subdomain points to unclaimed {provider} resource",
                                            'risk_level': "Critical",
                                            'details': {
                                                'subdomain': subdomain,
                                                'target': target,
                                                'provider': provider,
                                                'record_type': record_type
                                            },
                                            'recommendations': [
                                                'Claim the cloud resource immediately',
                                                'Update DNS records',
                                                'Review cloud resource lifecycle'
                                            ]
                                        })
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error checking cloud takeover for {subdomain}: {str(e)}")

    def _check_http_takeover(self, subdomain: str, result: ToolResult) -> None:
        """Check for HTTP-based takeover indicators"""
        try:
            for protocol in ['http', 'https']:
                try:
                    response = requests.get(
                        f"{protocol}://{subdomain}",
                        timeout=self.resolver.timeout,
                        allow_redirects=False
                    )
                    
                    # Check for common takeover indicators
                    indicators = [
                        'Domain not found',
                        'Domain not configured',
                        'Domain parked',
                        '404 Not Found',
                        'Parked Domain'
                    ]
                    
                    for indicator in indicators:
                        if indicator.lower() in response.text.lower():
                            result.add_finding({
                                'title': "Potential HTTP Takeover",
                                'description': f"Found takeover indicator in HTTP response",
                                'risk_level': "Medium",
                                'details': {
                                    'subdomain': subdomain,
                                    'protocol': protocol,
                                    'status_code': response.status_code,
                                    'indicator': indicator
                                },
                                'recommendations': [
                                    'Verify domain ownership',
                                    'Update DNS records',
                                    'Configure web service properly'
                                ]
                            })
                            break
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error checking HTTP takeover for {subdomain}: {str(e)}")

    def _verify_cloud_takeover(self, target: str, verification: Dict) -> bool:
        """Verify if cloud resource is actually vulnerable to takeover"""
        try:
            response = requests.get(f"https://{target}", timeout=self.resolver.timeout)
            
            # Check status code
            if response.status_code in verification['http_codes']:
                # Check response body patterns
                for pattern in verification['body_patterns']:
                    if pattern.lower() in response.text.lower():
                        return True
                        
        except:
            pass
            
        return False

def main():
    """Entry point for DNS takeover detector"""
    tool = DNSTakeoverDetector()
    return tool.main()

if __name__ == "__main__":
    main() 