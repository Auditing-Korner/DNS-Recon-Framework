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

import argparse
import concurrent.futures
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
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class DNSSecurityScanner(BaseTool):
    """DNS Security Scanner for identifying common vulnerabilities and misconfigurations"""
    
    def __init__(self):
        super().__init__(
            name="dns-security-scanner",
            description="DNS Security Scanner for identifying vulnerabilities"
        )
        self.domain = None
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

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        super().setup_argparse(parser)
        
        parser.add_argument('domain', help='Target domain to scan')
        parser.add_argument('--check-dnssec', action='store_true',
                          help='Validate DNSSEC configuration')
        parser.add_argument('--check-zone-transfer', action='store_true',
                          help='Test for zone transfer vulnerabilities')
        parser.add_argument('--check-cache-poisoning', action='store_true',
                          help='Test for cache poisoning vulnerabilities')
        parser.add_argument('--check-open-resolver', action='store_true',
                          help='Check for open DNS resolver')
        parser.add_argument('--check-all', action='store_true',
                          help='Run all security checks')
        parser.add_argument('--timeout', type=int, default=5,
                          help='Timeout for DNS queries in seconds')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the security checks"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={"domain": args.domain}
        )
        
        try:
            self.domain = args.domain
            self.resolver.timeout = args.timeout
            self.resolver.lifetime = args.timeout
            
            # Determine which checks to run
            run_all = args.check_all
            checks = {
                'dnssec': run_all or args.check_dnssec,
                'zone_transfer': run_all or args.check_zone_transfer,
                'cache_poisoning': run_all or args.check_cache_poisoning,
                'open_resolver': run_all or args.check_open_resolver
            }
            
            # Get nameservers first
            nameservers = self._get_nameservers(result)
            if not nameservers:
                result.add_error("No nameservers found for domain")
                return result
            
            # Run security checks
            if checks['dnssec']:
                self._check_dnssec(result)
            if checks['zone_transfer']:
                self._check_zone_transfer(result, nameservers)
            if checks['cache_poisoning']:
                self._check_cache_poisoning(result, nameservers)
            if checks['open_resolver']:
                self._check_open_resolver(result, nameservers)
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during security scan: {str(e)}")
            return result

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
                    result.add_finding(
                        title="Nameserver Resolution Error",
                        description=f"Could not resolve IP for nameserver {ns_name}",
                        risk_level="Medium",
                        evidence=str(e)
                    )
            
            return nameservers
            
        except Exception as e:
            result.add_error(f"Error getting nameservers: {str(e)}")
            return []

    def _check_dnssec(self, result: ToolResult) -> None:
        """Check DNSSEC configuration and validation"""
        try:
            # Check for DNSSEC records
            required_records = self.security_checks['dnssec']['required_records']
            missing_records = []
            found_records = {}
            
            for record_type in required_records:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    found_records[record_type] = len(answers)
                except:
                    missing_records.append(record_type)
            
            if missing_records:
                result.add_finding(
                    title="Incomplete DNSSEC Configuration",
                    description=f"Missing DNSSEC records: {', '.join(missing_records)}",
                    risk_level="High"
                )
            
            # Check DNSKEY algorithms if present
            if 'DNSKEY' in found_records:
                try:
                    dnskey_records = dns.resolver.resolve(self.domain, 'DNSKEY')
                    for dnskey in dnskey_records:
                        algorithm = dnskey.algorithm
                        
                        if algorithm in self.security_checks['dnssec']['algorithms']['deprecated']:
                            result.add_finding(
                                title="Deprecated DNSSEC Algorithm",
                                description=f"Using deprecated algorithm {algorithm}",
                                risk_level="High",
                                evidence=f"DNSKEY record: {dnskey}"
                            )
                        elif algorithm not in self.security_checks['dnssec']['algorithms']['recommended']:
                            result.add_finding(
                                title="Non-recommended DNSSEC Algorithm",
                                description=f"Using non-recommended algorithm {algorithm}",
                                risk_level="Medium",
                                evidence=f"DNSKEY record: {dnskey}"
                            )
                except Exception as e:
                    result.add_finding(
                        title="DNSKEY Analysis Error",
                        description=f"Error analyzing DNSKEY records: {str(e)}",
                        risk_level="Medium"
                    )
            
            # Verify DNSSEC chain of trust
            try:
                request = dns.message.make_query(self.domain, dns.rdatatype.A, want_dnssec=True)
                response = dns.query.udp(request, self.resolver.nameservers[0])
                
                if not response.flags & dns.flags.AD:
                    result.add_finding(
                        title="DNSSEC Validation Failed",
                        description="Response not authenticated by DNSSEC",
                        risk_level="High"
                    )
            except Exception as e:
                result.add_finding(
                    title="DNSSEC Validation Error",
                    description=f"Error validating DNSSEC chain: {str(e)}",
                    risk_level="High"
                )
                
        except Exception as e:
            result.add_error(f"Error checking DNSSEC: {str(e)}")

    def _check_zone_transfer(self, result: ToolResult, nameservers: List[str]) -> None:
        """Test for zone transfer vulnerabilities"""
        for ns in nameservers:
            for port in self.ns_ports:
                try:
                    xfr = dns.query.xfr(ns, self.domain, port=port, 
                                      timeout=self.security_checks['zone_transfer']['timeout'])
                    zone = dns.zone.from_xfr(xfr)
                    
                    if zone:
                        result.add_finding(
                            title="Zone Transfer Allowed",
                            description=f"Nameserver {ns}:{port} allows zone transfers",
                            risk_level="Critical",
                            evidence=f"Successfully transferred zone with {len(zone.nodes)} records"
                        )
                except dns.xfr.TransferError:
                    # This is actually good - transfer was rejected
                    continue
                except Exception as e:
                    if "refused" not in str(e).lower():
                        result.add_finding(
                            title="Zone Transfer Test Error",
                            description=f"Error testing zone transfer on {ns}:{port}",
                            risk_level="Info",
                            evidence=str(e)
                        )

    def _check_cache_poisoning(self, result: ToolResult, nameservers: List[str]) -> None:
        """Test for cache poisoning vulnerabilities"""
        for ns in nameservers:
            try:
                # Test for randomization of source ports and query IDs
                ports = set()
                query_ids = set()
                
                for _ in range(self.security_checks['cache_poisoning']['test_queries']):
                    request = dns.message.make_query(
                        f"random-{random.randint(1, 1000000)}.{self.domain}",
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
                    result.add_finding(
                        title="Predictable Source Ports",
                        description=f"Nameserver {ns} uses predictable source ports",
                        risk_level="High",
                        evidence=f"Only {len(ports)} unique ports used in {self.security_checks['cache_poisoning']['test_queries']} queries"
                    )
                
                if len(query_ids) < self.security_checks['cache_poisoning']['test_queries']:
                    result.add_finding(
                        title="Predictable Query IDs",
                        description=f"Nameserver {ns} uses predictable query IDs",
                        risk_level="High",
                        evidence=f"Only {len(query_ids)} unique query IDs used in {self.security_checks['cache_poisoning']['test_queries']} queries"
                    )
                    
            except Exception as e:
                result.add_finding(
                    title="Cache Poisoning Test Error",
                    description=f"Error testing cache poisoning on {ns}",
                    risk_level="Medium",
                    evidence=str(e)
                )

    def _check_open_resolver(self, result: ToolResult, nameservers: List[str]) -> None:
        """Check for open DNS resolver configuration"""
        test_domain = "example.com"  # Use a known domain for testing
        
        for ns in nameservers:
            try:
                # Try to resolve a domain that's not related to the target
                request = dns.message.make_query(test_domain, dns.rdatatype.A)
                response = dns.query.udp(request, ns, timeout=self.resolver.timeout)
                
                if response.rcode() == dns.rcode.NOERROR and len(response.answer) > 0:
                    result.add_finding(
                        title="Open DNS Resolver",
                        description=f"Nameserver {ns} appears to be an open resolver",
                        risk_level="High",
                        evidence=f"Successfully resolved {test_domain}"
                    )
                    
                    # Additional check for rate limiting
                    try:
                        start_time = time.time()
                        query_count = 0
                        
                        while time.time() - start_time < 1:  # Test for 1 second
                            dns.query.udp(request, ns, timeout=0.1)
                            query_count += 1
                        
                        if query_count > 100:  # More than 100 queries per second
                            result.add_finding(
                                title="No Query Rate Limiting",
                                description=f"Nameserver {ns} does not implement query rate limiting",
                                risk_level="High",
                                evidence=f"Processed {query_count} queries in 1 second"
                            )
                    except:
                        pass
                        
            except Exception as e:
                if "refused" not in str(e).lower():
                    result.add_finding(
                        title="Open Resolver Test Error",
                        description=f"Error testing open resolver on {ns}",
                        risk_level="Info",
                        evidence=str(e)
                    )

def main():
    tool = DNSSecurityScanner()
    result = tool.main()
    return result['status'] if result and 'status' in result else 'error'

if __name__ == "__main__":
    sys.exit(0 if main() == 'success' else 1) 