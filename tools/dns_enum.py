#!/usr/bin/env python3
"""
DNS Enumeration Tool

Performs comprehensive DNS enumeration and analysis:
- Record enumeration
- Zone transfers
- Subdomain discovery
- DNS security checks
- Infrastructure analysis
"""

import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
import socket
import sys
import os
import json
import re
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
import dns.dnssec
import dns.message
import dns.rdataclass
import concurrent.futures

# Import base tool and constants
from tool_interface import BaseTool, ToolResult
from constants import (
    SMTP_SECURITY_CHECKS,
    TAKEOVER_SIGNATURES,
    SECURITY_HEADERS,
    RECORD_TYPES,
    DNSSEC_RECORD_TYPES,
    DNSSEC_ALGORITHMS,
    DNSSEC_DIGEST_TYPES
)

class DNSEnumerator(BaseTool):
    """DNS Enumeration and Analysis Tool"""
    
    def __init__(self, framework_mode: bool = False):
        super().__init__(framework_mode)
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Setup tool-specific command line arguments"""
        parser.add_argument('domain', help='Target domain to enumerate')
        parser.add_argument('--record-types', 
                          default='A,AAAA,CNAME,MX,NS,TXT,SOA',
                          help='Comma-separated list of record types to query')
        parser.add_argument('--check-dnssec', 
                          action='store_true',
                          help='Enable DNSSEC checks')
        parser.add_argument('--check-wildcards', 
                          action='store_true',
                          help='Enable wildcard DNS detection')
        parser.add_argument('--nameserver',
                          help='Custom nameserver to use')
        parser.add_argument('--timeout',
                          type=int,
                          default=30,
                          help='Query timeout in seconds')
        
    def _run_tool(self, args: argparse.Namespace) -> ToolResult:
        """Run DNS enumeration with provided arguments"""
        try:
            # Configure resolver
            if args.nameserver:
                self.resolver.nameservers = [args.nameserver]
            self.resolver.timeout = float(args.timeout)
            self.resolver.lifetime = float(args.timeout)
            
            # Add metadata
            self.result.metadata["target_domain"] = args.domain
            self.result.metadata["record_types"] = args.record_types.split(',')
            self.result.metadata["nameserver"] = args.nameserver or "default"
            
            # Check for wildcard DNS records if enabled
            if args.check_wildcards:
                self._check_wildcards(args.domain)
            
            # Enumerate DNS records
            for record_type in args.record_types.split(','):
                try:
                    answers = self.resolver.resolve(args.domain, record_type)
                    for answer in answers:
                        self.result.add_finding({
                            'type': 'dns_record',
                            'record_type': record_type,
                            'value': str(answer),
                            'description': f'Found {record_type} record for {args.domain}',
                            'risk_level': 'Info',
                            'timestamp': datetime.now().isoformat()
                        })
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    self.log_message("warning", f"Domain {args.domain} does not exist")
                    break
                except Exception as e:
                    self.log_message("warning", f"Error querying {record_type} records: {str(e)}")
            
            # Check DNSSEC if enabled
            if args.check_dnssec:
                self._check_dnssec(args.domain)
            
            # Set final status
            self.result.status = "completed"
            return self.result
            
        except Exception as e:
            self.log_message("error", f"Error during DNS enumeration: {str(e)}")
            self.result.status = "error"
            return self.result
    
    def _check_wildcards(self, domain: str) -> None:
        """Check for wildcard DNS records"""
        try:
            # Generate a random subdomain
            random_sub = f"wildcard-test-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            test_domain = f"{random_sub}.{domain}"
            
            # Try to resolve the random subdomain
            try:
                answers = self.resolver.resolve(test_domain, 'A')
                self.result.add_finding({
                    'type': 'wildcard_dns',
                    'domain': domain,
                    'test_domain': test_domain,
                    'description': 'Wildcard DNS record detected',
                    'details': [str(rdata) for rdata in answers],
                    'risk_level': 'Medium',
                    'recommendations': [
                        'Review wildcard DNS configuration',
                        'Ensure wildcards are intentional and necessary',
                        'Consider security implications of wildcard records'
                    ],
                    'timestamp': datetime.now().isoformat()
                })
            except dns.resolver.NXDOMAIN:
                # No wildcard record found - this is normal
                pass
            except Exception as e:
                self.log_message("warning", f"Error checking wildcard records: {str(e)}")
                
        except Exception as e:
            self.log_message("warning", f"Error during wildcard check: {str(e)}")
    
    def _check_dnssec(self, domain: str) -> None:
        """Check DNSSEC configuration"""
        try:
            # Check for DNSSEC records
            for record_type in DNSSEC_RECORD_TYPES:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    for answer in answers:
                        finding = {
                            'type': 'dnssec_record',
                            'record_type': record_type,
                            'value': str(answer),
                            'description': f'Found DNSSEC {record_type} record',
                            'risk_level': 'Info',
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Add algorithm information for DNSKEY records
                        if record_type == 'DNSKEY':
                            algorithm = DNSSEC_ALGORITHMS.get(answer.algorithm, 'Unknown')
                            finding['details'] = {
                                'algorithm': algorithm,
                                'key_tag': answer.key_tag(),
                                'flags': answer.flags
                            }
                            
                            # Check for deprecated algorithms
                            if answer.algorithm in [1, 3, 5, 6, 7]:
                                finding['risk_level'] = 'High'
                                finding['recommendations'] = [
                                    'Update DNSSEC to use modern algorithms',
                                    'Consider using RSA/SHA-256 or ECDSA'
                                ]
                        
                        self.result.add_finding(finding)
                        
                except dns.resolver.NoAnswer:
                    continue
                except Exception as e:
                    self.log_message("warning", f"Error checking {record_type} records: {str(e)}")
            
        except Exception as e:
            self.log_message("warning", f"Error during DNSSEC check: {str(e)}")

def main():
    """Main entry point for standalone tool execution"""
    tool = DNSEnumerator()
    
    # Setup argument parser
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    tool.setup_argparse(parser)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run the tool
    result = tool.run(args)
    
    # Save results
    if not os.path.exists('results/dns_enum'):
        os.makedirs('results/dns_enum')
        
    output_file = f'results/dns_enum/{args.domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    tool.save_results(output_file)
    
    # Generate HTML report
    html_file = output_file.replace('.json', '.html')
    tool.generate_html_report(html_file)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
        