#!/usr/bin/env python3

import dns.resolver
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Optional, Dict
import itertools
import string

class DNSTLDBruteforcer:
    def __init__(self, domain: str, wordlist: Optional[str] = None, threads: int = 10, 
                 timeout: int = 2, tld_type: str = "all", bruteforce: bool = False,
                 min_length: int = 2, max_length: int = 3):
        self.base_domain = domain
        self.threads = threads
        self.timeout = timeout
        self.tld_type = tld_type.lower()
        self.bruteforce = bruteforce
        self.min_length = min_length
        self.max_length = max_length
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Categorized TLD lists
        self.tld_categories: Dict[str, List[str]] = {
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
        
        if self.bruteforce:
            self.tlds = self._generate_tld_combinations()
        elif wordlist:
            self.tlds = self._load_tlds(wordlist)
        else:
            if self.tld_type == "all":
                self.tlds = [tld for sublist in self.tld_categories.values() for tld in sublist]
            elif self.tld_type in self.tld_categories:
                self.tlds = self.tld_categories[self.tld_type]
            else:
                print(f"Invalid TLD type. Using all TLDs.")
                self.tlds = [tld for sublist in self.tld_categories.values() for tld in sublist]
        
        # Remove duplicates while preserving order
        self.tlds = list(dict.fromkeys(self.tlds))

    def _generate_tld_combinations(self) -> List[str]:
        """Generate TLD combinations for bruteforce"""
        chars = string.ascii_lowercase + string.digits + '-'
        combinations = []
        
        print(f"Generating TLD combinations (length {self.min_length}-{self.max_length})...")
        
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
        for length in range(self.min_length, self.max_length + 1):
            # Limit the character set for longer combinations to avoid excessive combinations
            if length > 2:
                chars = string.ascii_lowercase + '-'
            
            # Generate combinations with restrictions
            for combo in itertools.product(chars, repeat=length):
                tld = ''.join(combo)
                # Apply some rules to reduce unlikely combinations
                if (not tld.startswith('-') and not tld.endswith('-') and 
                    '--' not in tld and tld not in combinations):
                    combinations.append(tld)
        
        print(f"Generated {len(combinations)} TLD combinations")
        return combinations
        
    def _load_tlds(self, wordlist_path: str) -> List[str]:
        """Load TLDs from a wordlist file"""
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            sys.exit(1)

    def resolve_domain(self, tld: str) -> Optional[List[str]]:
        """Attempt to resolve a domain with specific TLD"""
        domain = f"{self.base_domain}.{tld}"
        try:
            answers = self.resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Try to get additional DNS records
            mx_records = []
            try:
                mx = self.resolver.resolve(domain, 'MX')
                mx_records = [str(rdata.exchange).rstrip('.') for rdata in mx]
            except:
                pass
                
            return [domain, ips, mx_records]
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except Exception as e:
            if self.bruteforce:
                # Suppress detailed errors during bruteforce to reduce noise
                return None
            print(f"Error resolving {domain}: {e}")
            return None

    def run(self):
        """Run the TLD bruteforce operation"""
        print(f"\nStarting DNS TLD bruteforce for base domain: {self.base_domain}")
        if self.bruteforce:
            print("Mode: Bruteforce")
        else:
            print(f"Mode: TLD category ({self.tld_type})")
        print(f"Testing {len(self.tlds)} TLDs with {self.threads} threads\n")
        
        found_domains = []
        total_tlds = len(self.tlds)
        processed = 0
        
        # Process TLDs in chunks to show progress
        chunk_size = 1000
        for i in range(0, total_tlds, chunk_size):
            chunk = self.tlds[i:i + chunk_size]
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                results = list(executor.map(self.resolve_domain, chunk))
            
            for result in results:
                if result:
                    domain, ips, mx_records = result
                    found_domains.append((domain, ips, mx_records))
                    print(f"[+] Found: {domain}")
                    print(f"    IP(s): {', '.join(ips)}")
                    if mx_records:
                        print(f"    MX: {', '.join(mx_records)}")
                    print()
            
            processed += len(chunk)
            if self.bruteforce:
                print(f"Progress: {processed}/{total_tlds} TLDs tested ({(processed/total_tlds)*100:.1f}%)")
        
        print(f"\nBruteforce complete. Found {len(found_domains)} valid domains.")
        return found_domains

def main():
    parser = argparse.ArgumentParser(description='DNS TLD Bruteforcer')
    parser.add_argument('domain', help='Base domain name without TLD (e.g., "example")')
    parser.add_argument('-w', '--wordlist', help='Path to TLD wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=2, help='Timeout in seconds for DNS queries (default: 2)')
    parser.add_argument('--type', choices=['all', 'common', 'country', 'business', 'tech'],
                        default='all', help='Type of TLDs to check (default: all)')
    parser.add_argument('-b', '--bruteforce', action='store_true',
                        help='Enable TLD bruteforce mode')
    parser.add_argument('--min-length', type=int, default=2,
                        help='Minimum TLD length for bruteforce mode (default: 2)')
    parser.add_argument('--max-length', type=int, default=3,
                        help='Maximum TLD length for bruteforce mode (default: 3)')
    
    args = parser.parse_args()
    
    bruteforcer = DNSTLDBruteforcer(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        tld_type=args.type,
        bruteforce=args.bruteforce,
        min_length=args.min_length,
        max_length=args.max_length
    )
    
    try:
        bruteforcer.run()
    except KeyboardInterrupt:
        print("\nBruteforce interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main() 