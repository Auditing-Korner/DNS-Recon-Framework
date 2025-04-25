#!/usr/bin/env python3

import dns.resolver
import dns.exception
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import itertools
import string
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Any
from rich.console import Console

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class TLDBruteforcer(BaseTool):
    """TLD Bruteforce Discovery Tool"""
    
    def __init__(self):
        super().__init__(
            name="tld_brute",
            description="TLD Bruteforce Discovery Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run TLD bruteforce with provided arguments"""
        domain = self.get_param('domain')
        record_types = self.get_param('record_types', 'all').split(',')
        timeout = self.get_param('timeout', 3)
        threads = self.get_param('threads', 10)
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        try:
            # Load TLD list
            tld_file = Path(__file__).parent / 'data' / 'tlds.txt'
            if not tld_file.exists():
                result.add_error(f"TLD list file not found: {tld_file}")
                return
                
            with open(tld_file) as f:
                tlds = [line.strip() for line in f if line.strip()]
                
            # Extract base domain
            base_name = domain.split('.')[0]
            
            # Test TLDs in parallel
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_tld = {
                    executor.submit(self._check_tld, base_name, tld): tld 
                    for tld in tlds
                }
                
                for future in concurrent.futures.as_completed(future_to_tld):
                    tld = future_to_tld[future]
                    try:
                        domain_info = future.result()
                        if domain_info:
                            result.add_finding({
                                'title': 'TLD Domain Found',
                                'description': f'Found active domain {domain_info["domain"]}',
                                'risk_level': 'Info',
                                'details': domain_info
                            })
                            
                            # Check additional records if requested
                            if 'all' in record_types:
                                self._check_additional_records(domain_info['domain'], result)
                                
                    except Exception as e:
                        result.add_warning(f"Error checking {tld}: {str(e)}")
                    
        except Exception as e:
            result.add_error(f"Error during TLD bruteforce: {str(e)}")
            
    def _check_tld(self, base_domain: str, tld: str) -> Optional[Dict]:
        """Check if a domain exists with the given TLD"""
        domain = f"{base_domain}.{tld}"
        try:
            # Get A records
            answers = self.resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Try to get MX records
            mx_records = []
            try:
                mx_answers = self.resolver.resolve(domain, 'MX')
                mx_records = [str(rdata.exchange).rstrip('.') for rdata in mx_answers]
            except:
                pass
            
            # Try to get NS records
            ns_records = []
            try:
                ns_answers = self.resolver.resolve(domain, 'NS')
                ns_records = [str(rdata).rstrip('.') for rdata in ns_answers]
            except:
                pass
            
            return {
                "domain": domain,
                "tld": tld,
                "ips": ips,
                "mx_records": mx_records,
                "ns_records": ns_records,
                "timestamp": datetime.now().isoformat()
            }
            
        except:
            return None
            
    def _check_additional_records(self, domain: str, result: ToolResult) -> None:
        """Check additional record types for a domain"""
        record_types = ['AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                result.add_finding({
                    'title': f'Additional Records Found',
                    'description': f'Found {record_type} records for {domain}',
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'record_type': record_type,
                        'records': [str(rr) for rr in answers]
                    }
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as e:
                result.add_warning(f"Error checking {record_type} records for {domain}: {str(e)}")

def main():
    """Entry point for TLD bruteforce tool"""
    tool = TLDBruteforcer()
    return tool.main()

if __name__ == "__main__":
    main() 