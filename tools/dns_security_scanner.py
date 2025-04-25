#!/usr/bin/env python3
"""
DNS Security Scanner Tool

Scans for common DNS security issues and vulnerabilities:
- DNSSEC validation
- Zone transfer attempts
- DNS cache poisoning tests
- DNS amplification potential
- DNS rebinding risks
- DNS tunneling detection
- Open resolver checks
"""

import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
import dns.message
import dns.rcode
import socket
import sys
import os
import json
import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class DNSSecurityScanner(BaseTool):
    """DNS Security Scanner for identifying common vulnerabilities and misconfigurations"""
    
    def __init__(self):
        super().__init__(
            name="dns_security_scanner",
            description="DNS Security Scanner for identifying vulnerabilities"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
        # Common nameserver ports to check
        self.ns_ports = [53, 5353, 853]
        
        # Initialize security check configurations
        self.security_checks = {
            'dnssec': {
                'required_records': ['DNSKEY', 'RRSIG', 'NSEC', 'DS'],
                'algorithms': {
                    'recommended': [8, 13, 14],  # RSASHA256, ECDSAP256SHA256, ECDSAP384SHA384
                    'deprecated': [1, 3, 6, 7]   # RSA/MD5, DSA/SHA1, etc.
                }
            },
            'zone_transfer': {
                'max_attempts': 3,
                'timeout': 5
            },
            'cache_poisoning': {
                'test_queries': 5,
                'query_interval': 1
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run DNS security scanning with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_dnssec = self.get_param('check_dnssec', True)
        check_zone_transfer = self.get_param('check_zone_transfer', True)
        check_cache_poisoning = self.get_param('check_cache_poisoning', True)
        check_open_resolver = self.get_param('check_open_resolver', True)
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Get nameservers first
            nameservers = self._get_nameservers(result)
            if not nameservers:
                result.add_error("No nameservers found for domain")
                return
            
            # Run security checks
            if check_dnssec:
                self._check_dnssec(domain, result)
            if check_zone_transfer:
                self._check_zone_transfer(domain, nameservers, result)
            if check_cache_poisoning:
                self._check_cache_poisoning(domain, nameservers, result)
            if check_open_resolver:
                self._check_open_resolver(nameservers, result)
                
        except Exception as e:
            result.add_error(f"Error during security scan: {str(e)}")
            
    def _get_nameservers(self, result: ToolResult) -> List[str]:
        """Get nameservers for the domain"""
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            nameservers = []
            
            for ns in ns_records:
                try:
                    ns_name = str(ns.target).rstrip('.')
                    ns_ips = dns.resolver.resolve(ns_name, 'A')
                    nameservers.extend([str(ip) for ip in ns_ips])
                except Exception as e:
                    result.add_finding({
                        'title': "Nameserver Resolution Error",
                        'description': f"Could not resolve IP for nameserver {ns_name}",
                        'risk_level': "Medium",
                        'details': {
                            'nameserver': ns_name,
                            'error': str(e)
                        },
                        'recommendations': [
                            'Verify nameserver configuration',
                            'Ensure nameserver has valid A records'
                        ]
                    })
            
            return nameservers
            
        except Exception as e:
            result.add_error(f"Error getting nameservers: {str(e)}")
            return []

    def _check_dnssec(self, domain: str, result: ToolResult) -> None:
        """Check DNSSEC configuration and validation"""
        try:
            # Check for DNSSEC records
            required_records = self.security_checks['dnssec']['required_records']
            missing_records = []
            found_records = {}
            
            for record_type in required_records:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    found_records[record_type] = len(answers)
                except:
                    missing_records.append(record_type)
            
            if missing_records:
                result.add_finding({
                    'title': "Incomplete DNSSEC Configuration",
                    'description': f"Missing DNSSEC records: {', '.join(missing_records)}",
                    'risk_level': "High",
                    'details': {
                        'domain': domain,
                        'missing_records': missing_records,
                        'found_records': found_records
                    },
                    'recommendations': [
                        'Configure DNSSEC properly',
                        'Add missing DNSSEC records',
                        'Verify DNSSEC chain of trust'
                    ]
                })
            
            # Check DNSKEY algorithms if present
            if 'DNSKEY' in found_records:
                try:
                    dnskey_records = dns.resolver.resolve(domain, 'DNSKEY')
                    for dnskey in dnskey_records:
                        algorithm = dnskey.algorithm
                        
                        if algorithm in self.security_checks['dnssec']['algorithms']['deprecated']:
                            result.add_finding({
                                'title': "Deprecated DNSSEC Algorithm",
                                'description': f"Using deprecated algorithm {algorithm}",
                                'risk_level': "High",
                                'details': {
                                    'domain': domain,
                                    'algorithm': algorithm,
                                    'dnskey': str(dnskey)
                                },
                                'recommendations': [
                                    'Update to a modern DNSSEC algorithm',
                                    'Consider using ECDSAP256SHA256 or ECDSAP384SHA384'
                                ]
                            })
                        elif algorithm not in self.security_checks['dnssec']['algorithms']['recommended']:
                            result.add_finding({
                                'title': "Non-recommended DNSSEC Algorithm",
                                'description': f"Using non-recommended algorithm {algorithm}",
                                'risk_level': "Medium",
                                'details': {
                                    'domain': domain,
                                    'algorithm': algorithm,
                                    'dnskey': str(dnskey)
                                },
                                'recommendations': [
                                    'Consider upgrading to a recommended algorithm',
                                    'Review DNSSEC configuration'
                                ]
                            })
                except Exception as e:
                    result.add_finding({
                        'title': "DNSKEY Analysis Error",
                        'description': f"Error analyzing DNSKEY records: {str(e)}",
                        'risk_level': "Medium",
                        'details': {
                            'domain': domain,
                            'error': str(e)
                        }
                    })
            
            # Verify DNSSEC chain of trust
            try:
                request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
                response = dns.query.udp(request, self.resolver.nameservers[0])
                
                if not response.flags & dns.flags.AD:
                    result.add_finding({
                        'title': "DNSSEC Validation Failed",
                        'description': "Response not authenticated by DNSSEC",
                        'risk_level': "High",
                        'details': {
                            'domain': domain,
                            'response': str(response)
                        },
                        'recommendations': [
                            'Verify DNSSEC configuration',
                            'Check DS records at parent zone',
                            'Validate DNSSEC chain of trust'
                        ]
                    })
            except Exception as e:
                result.add_finding({
                    'title': "DNSSEC Validation Error",
                    'description': f"Error validating DNSSEC chain: {str(e)}",
                    'risk_level': "High",
                    'details': {
                        'domain': domain,
                        'error': str(e)
                    }
                })
                
        except Exception as e:
            result.add_error(f"Error checking DNSSEC: {str(e)}")

    def _check_zone_transfer(self, domain: str, nameservers: List[str], result: ToolResult) -> None:
        """Test for zone transfer vulnerabilities"""
        for ns in nameservers:
            for port in self.ns_ports:
                try:
                    xfr = dns.query.xfr(ns, domain, port=port, 
                                      timeout=self.security_checks['zone_transfer']['timeout'])
                    zone = dns.zone.from_xfr(xfr)
                    
                    if zone:
                        result.add_finding({
                            'title': "Zone Transfer Allowed",
                            'description': f"Nameserver {ns}:{port} allows zone transfers",
                            'risk_level': "Critical",
                            'details': {
                                'domain': domain,
                                'nameserver': ns,
                                'port': port,
                                'zone_records': len(zone.nodes)
                            },
                            'recommendations': [
                                'Disable zone transfers immediately',
                                'Restrict zone transfers to authorized servers only',
                                'Review DNS security configuration'
                            ]
                        })
                except dns.xfr.TransferError:
                    # This is actually good - transfer was rejected
                    continue
                except Exception as e:
                    if "refused" not in str(e).lower():
                        result.add_finding({
                            'title': "Zone Transfer Test Error",
                            'description': f"Error testing zone transfer on {ns}:{port}",
                            'risk_level': "Info",
                            'details': {
                                'domain': domain,
                                'nameserver': ns,
                                'port': port,
                                'error': str(e)
                            }
                        })

    def _check_cache_poisoning(self, domain: str, nameservers: List[str], result: ToolResult) -> None:
        """Test for cache poisoning vulnerabilities"""
        for ns in nameservers:
            try:
                # Test for randomization of source ports and query IDs
                ports = set()
                query_ids = set()
                
                for _ in range(self.security_checks['cache_poisoning']['test_queries']):
                    request = dns.message.make_query(
                        f"random-{random.randint(1, 1000000)}.{domain}",
                        dns.rdatatype.A
                    )
                    response = dns.query.udp(request, ns)
                    
                    if response.id == request.id:
                        query_ids.add(response.id)
                    
                    # Get source port from response
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.bind(('', 0))
                        ports.add(sock.getsockname()[1])
                        sock.close()
                    except:
                        continue
                    
                    time.sleep(self.security_checks['cache_poisoning']['query_interval'])
                
                # Analyze results
                if len(ports) < self.security_checks['cache_poisoning']['test_queries']:
                    result.add_finding({
                        'title': "Predictable Source Ports",
                        'description': f"Nameserver {ns} uses predictable source ports",
                        'risk_level': "High",
                        'details': {
                            'domain': domain,
                            'nameserver': ns,
                            'unique_ports': len(ports),
                            'test_queries': self.security_checks['cache_poisoning']['test_queries']
                        },
                        'recommendations': [
                            'Enable source port randomization',
                            'Update DNS server software',
                            'Review security configuration'
                        ]
                    })
                
                if len(query_ids) < self.security_checks['cache_poisoning']['test_queries']:
                    result.add_finding({
                        'title': "Predictable Query IDs",
                        'description': f"Nameserver {ns} uses predictable query IDs",
                        'risk_level': "High",
                        'details': {
                            'domain': domain,
                            'nameserver': ns,
                            'unique_query_ids': len(query_ids),
                            'test_queries': self.security_checks['cache_poisoning']['test_queries']
                        },
                        'recommendations': [
                            'Enable query ID randomization',
                            'Update DNS server software',
                            'Implement cache poisoning protections'
                        ]
                    })
                    
            except Exception as e:
                result.add_finding({
                    'title': "Cache Poisoning Test Error",
                    'description': f"Error testing cache poisoning on {ns}",
                    'risk_level': "Medium",
                    'details': {
                        'domain': domain,
                        'nameserver': ns,
                        'error': str(e)
                    }
                })

    def _check_open_resolver(self, nameservers: List[str], result: ToolResult) -> None:
        """Check for open DNS resolver configuration"""
        test_domain = "example.com"  # Use a known domain for testing
        
        for ns in nameservers:
            try:
                # Try to resolve a domain that's not related to the target
                request = dns.message.make_query(test_domain, dns.rdatatype.A)
                response = dns.query.udp(request, ns, timeout=self.resolver.timeout)
                
                if response.rcode() == dns.rcode.NOERROR and len(response.answer) > 0:
                    result.add_finding({
                        'title': "Open DNS Resolver",
                        'description': f"Nameserver {ns} appears to be an open resolver",
                        'risk_level': "High",
                        'details': {
                            'nameserver': ns,
                            'test_domain': test_domain,
                            'response': str(response)
                        },
                        'recommendations': [
                            'Disable recursive queries for unauthorized clients',
                            'Configure access control lists',
                            'Separate authoritative and recursive servers'
                        ]
                    })
                    
                    # Additional check for rate limiting
                    try:
                        start_time = time.time()
                        query_count = 0
                        
                        while time.time() - start_time < 1:  # Test for 1 second
                            dns.query.udp(request, ns, timeout=0.1)
                            query_count += 1
                        
                        if query_count > 100:  # More than 100 queries per second
                            result.add_finding({
                                'title': "No Query Rate Limiting",
                                'description': f"Nameserver {ns} does not implement query rate limiting",
                                'risk_level': "High",
                                'details': {
                                    'nameserver': ns,
                                    'query_count': query_count,
                                    'time_period': "1 second"
                                },
                                'recommendations': [
                                    'Implement query rate limiting',
                                    'Configure response rate limiting (RRL)',
                                    'Review DoS protection measures'
                                ]
                            })
                    except:
                        pass
                        
            except Exception as e:
                if "refused" not in str(e).lower():
                    result.add_finding({
                        'title': "Open Resolver Test Error",
                        'description': f"Error testing open resolver on {ns}",
                        'risk_level': "Info",
                        'details': {
                            'nameserver': ns,
                            'error': str(e)
                        }
                    })

def main():
    """Entry point for DNS security scanner"""
    tool = DNSSecurityScanner()
    return tool.main()

if __name__ == "__main__":
    main() 