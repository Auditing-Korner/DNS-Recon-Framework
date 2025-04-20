#!/usr/bin/env python3

import dns.resolver
import time
import argparse
import json
import os
import concurrent.futures
import sys
from concurrent.futures import ThreadPoolExecutor
import itertools
import string
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from rich.console import Console

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class TLDBruteforcer(BaseTool):
    def __init__(self):
        super().__init__(
            name="tld-brute",
            description="Multi-threaded TLD discovery"
        )
        self.console = Console()
        self.resolver = dns.resolver.Resolver()
        self.tld_categories = {
            "common": [
                "com", "net", "org", "edu", "gov", "mil", "int", "info",
                "biz", "xyz", "online", "site", "app", "dev", "io", "me"
            ],
            "country": [
                # European ccTLDs
                "pt", "es", "fr", "de", "it", "uk", "ie", "nl", "be", "lu",
                "ch", "at", "dk", "no", "se", "fi", "is", "pl", "cz", "sk",
                "hu", "ro", "bg", "gr", "mt", "cy", "ee", "lv", "lt",
                # Other major ccTLDs
                "br", "mx", "ar", "cl", "co", "pe", "ve", "au", "nz", "jp",
                "cn", "kr", "in", "ru", "za", "ng", "eg", "ma", "ae", "il",
                "tr", "ca"
            ],
            "business": [
                "shop", "store", "business", "company", "ltd", "inc", "cloud",
                "tech", "digital", "solutions", "consulting", "group", "agency",
                "services", "media", "marketing", "ventures"
            ],
            "tech": [
                "ai", "api", "app", "dev", "cloud", "code", "crypto", "data",
                "tech", "software", "systems", "network", "web", "hosting"
            ]
        }

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        super().setup_argparse(parser)
        
        parser.add_argument('domain', help='Base domain name without TLD')
        parser.add_argument('-w', '--wordlist', help='Path to TLD wordlist file')
        parser.add_argument('-t', '--threads', type=int, default=10,
                          help='Number of threads (default: 10)')
        parser.add_argument('--timeout', type=int, default=2,
                          help='Timeout in seconds for DNS queries (default: 2)')
        parser.add_argument('--type', choices=['all', 'common', 'country', 'business', 'tech'],
                          default='all', help='Type of TLDs to check (default: all)')
        parser.add_argument('-b', '--bruteforce', action='store_true',
                          help='Enable TLD bruteforce mode')
        parser.add_argument('--min-length', type=int, default=2,
                          help='Minimum TLD length for bruteforce mode (default: 2)')
        parser.add_argument('--max-length', type=int, default=3,
                          help='Maximum TLD length for bruteforce mode (default: 3)')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
        # Initialize result
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[]
        )
        
        # Configure resolver
        self.resolver.timeout = args.timeout
        self.resolver.lifetime = args.timeout
        
        # Get TLDs to test
        if args.bruteforce:
            tlds = self._generate_tld_combinations(args.min_length, args.max_length)
        elif args.wordlist:
            tlds = self._load_tlds(args.wordlist)
        else:
            if args.type == "all":
                tlds = [tld for sublist in self.tld_categories.values() for tld in sublist]
            elif args.type in self.tld_categories:
                tlds = self.tld_categories[args.type]
            else:
                result.add_warning("Invalid TLD type. Using all TLDs.")
                tlds = [tld for sublist in self.tld_categories.values() for tld in sublist]
        
        # Remove duplicates while preserving order
        tlds = list(dict.fromkeys(tlds))
        
        # Start bruteforce
        start_time = datetime.now()
        found_domains = []
        total_tlds = len(tlds)
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_tld = {
                executor.submit(self._check_tld, args.domain, tld): tld 
                for tld in tlds
            }
            
            for future in concurrent.futures.as_completed(future_to_tld):
                tld = future_to_tld[future]
                try:
                    domain_info = future.result()
                    if domain_info:
                        found_domains.append(domain_info)
                        result.add_finding(
                            title=f"TLD variant found: {domain_info['domain']}",
                            description=f"IPs: {', '.join(domain_info['ips'])}",
                            risk_level="Info",
                            evidence=json.dumps(domain_info, indent=2)
                        )
                except Exception as e:
                    result.add_error(f"Error checking {tld}: {str(e)}")
        
        # Add statistics to metadata
        result.metadata = {
            "total_tlds_tested": total_tlds,
            "valid_domains_found": len(found_domains),
            "domains_with_mx": sum(1 for d in found_domains if d.get('mx_records')),
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration": (datetime.now() - start_time).total_seconds()
        }
        
        return result

    def _generate_tld_combinations(self, min_length: int, max_length: int) -> List[str]:
        """Generate TLD combinations for bruteforce"""
        chars = string.ascii_lowercase + string.digits + '-'
        combinations = []
        
        # Add common TLD patterns
        patterns = [
            'co.{}',  # co.uk, co.jp
            'com.{}', # com.br, com.au
            'net.{}', # net.cn
            'org.{}', # org.uk
            'edu.{}', # edu.au
            'gov.{}', # gov.uk
        ]
        
        # Add two-letter country codes first
        for combo in itertools.product(string.ascii_lowercase, repeat=2):
            combinations.append(''.join(combo))
        
        # Add pattern-based TLDs
        for pattern in patterns:
            for combo in itertools.product(string.ascii_lowercase, repeat=2):
                combinations.append(pattern.format(''.join(combo)))
        
        # Add regular combinations
        for length in range(min_length, max_length + 1):
            if length > 2:
                chars = string.ascii_lowercase + '-'
            
            for combo in itertools.product(chars, repeat=length):
                tld = ''.join(combo)
                if (not tld.startswith('-') and not tld.endswith('-') and 
                    '--' not in tld and tld not in combinations):
                    combinations.append(tld)
        
        return combinations

    def _load_tlds(self, wordlist_path: str) -> List[str]:
        """Load TLDs from a wordlist file"""
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except Exception as e:
            self.console.print(f"[red]Error loading wordlist: {e}")
            return []

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
                mx = self.resolver.resolve(domain, 'MX')
                mx_records = [str(rdata.exchange).rstrip('.') for rdata in mx]
            except:
                pass
            
            return {
                "domain": domain,
                "ips": ips,
                "mx_records": mx_records
            }
        except:
            return None

def main():
    tool = TLDBruteforcer()
    return tool.main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1) 