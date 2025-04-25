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
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import dns.dnssec
import dns.message
import dns.rdataclass
import concurrent.futures

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Constants moved to a separate section for better organization
from .constants import (
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
    
    def __init__(self):
        super().__init__(
            name="dns_enum",
            description="Comprehensive DNS enumeration and analysis"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run DNS enumeration with provided arguments"""
        try:
            # Get parameters with defaults
            domain = self.get_param('domain')
            if not domain:
                result.success = False
                result.add_error("Domain parameter is required")
                return

            record_types = self.get_param('record_types', 'A,AAAA,CNAME,MX,NS,TXT,SOA').split(',')
            check_dnssec = self.get_param('check_dnssec', False)
            check_wildcards = self.get_param('check_wildcards', False)
            nameserver = self.get_param('nameserver')
            timeout = self.get_param('timeout', 30)
            
            # Configure resolver
            if nameserver:
                self.resolver.nameservers = [nameserver]
            self.resolver.timeout = float(timeout)
            self.resolver.lifetime = float(timeout)
            
            # Initialize findings list
            findings = []
            
            # Check for wildcard DNS records if enabled
            if check_wildcards:
                self._check_wildcards(domain, result)
            
            # Enumerate DNS records
            for record_type in record_types:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    for answer in answers:
                        finding = {
                            'type': 'dns_record',
                            'record_type': record_type,
                            'value': str(answer),
                            'description': f'Found {record_type} record for {domain}',
                            'risk_level': 'Info'
                        }
                        result.add_finding(finding)
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    result.add_warning(f"Domain {domain} does not exist")
                    break
                except Exception as e:
                    result.add_warning(f"Error querying {record_type} records: {str(e)}")
            
            # Check DNSSEC if enabled
            if check_dnssec:
                self._check_dnssec(domain, result)
            
            # Set success if we got this far
            result.success = True
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during DNS enumeration: {str(e)}")
    
    def _check_wildcards(self, domain: str, result: ToolResult) -> None:
        """Check for wildcard DNS records"""
        try:
            # Generate a random subdomain
            random_sub = f"wildcard-test-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            test_domain = f"{random_sub}.{domain}"
            
            # Try to resolve the random subdomain
            try:
                answers = self.resolver.resolve(test_domain, 'A')
                result.add_finding({
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
                    ]
                })
            except dns.resolver.NXDOMAIN:
                # No wildcard record found - this is normal
                pass
            except Exception as e:
                result.add_warning(f"Error checking wildcard records: {str(e)}")
                
        except Exception as e:
            result.add_warning(f"Error during wildcard check: {str(e)}")
    
    def _check_dnssec(self, domain: str, result: ToolResult) -> None:
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
                            'risk_level': 'Info'
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
                        
                        result.add_finding(finding)
                        
                except dns.resolver.NoAnswer:
                    continue
                except Exception as e:
                    result.add_warning(f"Error checking {record_type} records: {str(e)}")
            
        except Exception as e:
            result.add_warning(f"Error during DNSSEC check: {str(e)}")

def main():
    """Main entry point for the tool"""
    tool = DNSEnumerator()
    
    # When running as a standalone tool
    if len(sys.argv) > 1:
        # Convert command line arguments to parameters
        params = {
            'domain': sys.argv[1] if len(sys.argv) > 1 else None,
            'record_types': sys.argv[2] if len(sys.argv) > 2 else 'A,AAAA,CNAME,MX,NS,TXT,SOA',
            'check_dnssec': '--check-dnssec' in sys.argv,
            'check_wildcards': '--check-wildcards' in sys.argv
        }
    else:
        params = {}
    
    # Run the tool
    result = tool.run(params)
    
    # Print results
    print(json.dumps(result, indent=4))
    
    return result

if __name__ == '__main__':
    main()
        