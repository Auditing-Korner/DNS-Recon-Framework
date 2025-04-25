#!/usr/bin/env python3
"""
TLD Bruteforce Tool

Discovers registered top-level domains for a given name:
- Tests against all IANA TLDs
- Validates DNS records
- Checks domain registration
- Identifies defensive registrations
- Maps brand presence
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import whois
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

class TLDBruteforcer(BaseTool):
    """TLD Bruteforce Tool"""
    
    def __init__(self):
        super().__init__(
            name="tld_brute",
            description="TLD Bruteforce Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Load TLD list
        self.tlds = self._load_tlds()
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run TLD bruteforce with provided arguments"""
        domain = self.get_param('domain').split('.')[0]  # Get base name
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_whois = self.get_param('check_whois', True)
        max_threads = int(self.get_param('threads', 10))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Check each TLD
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                for tld in self.tlds:
                    test_domain = f"{domain}.{tld}"
                    futures.append(executor.submit(
                        self._check_domain,
                        test_domain,
                        check_whois,
                        result
                    ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in TLD check: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during TLD bruteforce: {str(e)}")
            
    def _load_tlds(self) -> List[str]:
        """Load list of TLDs from file or use default list"""
        try:
            tld_file = Path(__file__).parent / 'data' / 'tlds.txt'
            if tld_file.exists():
                with open(tld_file) as f:
                    return [line.strip().lower() for line in f if line.strip()]
        except:
            pass
            
        # Return default list if file not found
        return [
            'com', 'net', 'org', 'info', 'biz', 'edu', 'gov', 'mil',
            'us', 'uk', 'ca', 'au', 'de', 'jp', 'fr', 'ru', 'ch', 'it',
            'nl', 'se', 'no', 'es', 'mil', 'io', 'co', 'ai', 'app', 'dev'
        ]

    def _check_domain(self, domain: str, check_whois: bool, result: ToolResult) -> None:
        """Check if domain exists and gather information"""
        try:
            # Check DNS records
            found_records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    found_records[record_type] = [str(rr) for rr in answers]
                except:
                    continue
            
            if found_records:
                finding = {
                    'title': "Domain Registered",
                    'description': f"Found active DNS records for {domain}",
                    'risk_level': "Info",
                    'details': {
                        'domain': domain,
                        'records': found_records
                    },
                    'recommendations': [
                        'Verify domain ownership',
                        'Review DNS configuration',
                        'Monitor domain activity'
                    ]
                }
                
                # Check WHOIS if enabled
                if check_whois:
                    try:
                        w = whois.whois(domain)
                        if w.domain_name:
                            finding['details']['whois'] = {
                                'registrar': w.registrar,
                                'creation_date': str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                                'expiration_date': str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
                                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
                            }
                            
                            # Check for potential defensive registration
                            if not found_records.get('A') and not found_records.get('AAAA'):
                                finding['title'] = "Potential Defensive Registration"
                                finding['description'] = f"Domain {domain} registered but not resolving"
                                finding['risk_level'] = "Low"
                                finding['recommendations'].extend([
                                    'Confirm defensive registration strategy',
                                    'Monitor for cybersquatting',
                                    'Review domain portfolio'
                                ])
                    except:
                        pass
                        
                result.add_finding(finding)
                
        except Exception as e:
            result.add_warning(f"Error checking domain {domain}: {str(e)}")

def main():
    """Entry point for TLD bruteforcer"""
    tool = TLDBruteforcer()
    return tool.main()

if __name__ == "__main__":
    main() 