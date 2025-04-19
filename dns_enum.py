#!/usr/bin/env python3
"""
Advanced DNS Enumeration Tool

A comprehensive tool for DNS reconnaissance with optimized performance:
- DNS record enumeration for all common record types
- Nameserver detection and analysis
- Zone transfer attempts
- Memory-efficient subdomain brute-forcing
- Wildcard detection and filtering
- DNS delegation and infrastructure analysis
- Result caching to resume interrupted scans
- Export to multiple formats (JSON, CSV, TXT)

Usage:
    python dns_enum.py domain.com [options]

Requirements:
    pip install dnspython requests tqdm colorama pandas
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import re
import signal
import socket
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.name
    import dns.reversename
    import requests
    from colorama import Fore, Style, init
    from tqdm import tqdm
except ImportError:
    print("Required modules not found. Please install them with:")
    print("pip install dnspython requests tqdm colorama")
    sys.exit(1)

# Optional imports
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

# Common wordlists for subdomain bruteforce
WORDLIST_PATHS = {
    "tiny": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    "small": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt",
    "medium": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "large": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    "xl": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
    "dns-jhaddix": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
    "bitquark": "https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000"
}

# Cloud and hosting provider detection signatures
CLOUD_PROVIDERS = {
    # Amazon Web Services
    "AWS": {
        "domains": [
            "amazonaws.com", "amazon.com", "aws.amazon.com", "awsdns-", 
            "elasticbeanstalk.com", "cloudfront.net", "elb.amazonaws.com",
            "s3.amazonaws.com", "s3-", "execute-api", "lambda-url"
        ],
        "cnames": [
            r".*\.elb\.amazonaws\.com$",
            r".*\.s3[-\.].*\.amazonaws\.com$",
            r".*\.cloudfront\.net$",
            r".*\.execute-api\.[a-z0-9-]+\.amazonaws\.com$"
        ],
        "ip_prefixes": [
            # These are partial - AWS has many IP ranges
            "13.32.0.0/15", "13.35.0.0/16", "52.92.0.0/14", "52.95.0.0/16",
            "54.231.0.0/17", "54.192.0.0/12"
        ]
    },
    # Microsoft Azure
    "Azure": {
        "domains": [
            "azure.com", "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
            "trafficmanager.net", "azureedge.net", "azure-api.net", 
            "azurecontainer.io", "azurecr.io", "core.windows.net", "database.windows.net"
        ],
        "cnames": [
            r".*\.azurewebsites\.net$",
            r".*\.cloudapp\.azure\.com$",
            r".*\.trafficmanager\.net$",
            r".*\.blob\.core\.windows\.net$"
        ],
        "ip_prefixes": [
            "13.104.0.0/14", "13.64.0.0/11", "13.96.0.0/13", "20.33.0.0/16",
            "40.64.0.0/10", "52.136.0.0/13", "104.208.0.0/13"
        ]
    },
    # Google Cloud Platform
    "GCP": {
        "domains": [
            "googleapis.com", "appspot.com", "googleusercontent.com",
            "run.app", "cloud.goog", "cloudfunctions.net", "firebaseapp.com"
        ],
        "cnames": [
            r".*\.appspot\.com$",
            r".*\.run\.app$",
            r".*\.cloudfunctions\.net$"
        ],
        "ip_prefixes": [
            "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14",
            "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17"
        ]
    },
    # Cloudflare
    "Cloudflare": {
        "domains": [
            "cloudflare.com", "cloudflare.net", "workers.dev", "pages.dev"
        ],
        "cnames": [
            r".*\.cloudflare\.net$",
            r".*\.pages\.dev$",
            r".*\.workers\.dev$"
        ],
        "ip_prefixes": [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/12",
            "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
            "197.234.240.0/22", "198.41.128.0/17"
        ]
    },
    # Digital Ocean
    "DigitalOcean": {
        "domains": [
            "digitalocean.com", "digitaloceanspaces.com", "ondigitalocean.app"
        ],
        "cnames": [
            r".*\.digitaloceanspaces\.com$",
            r".*\.ondigitalocean\.app$"
        ],
        "ip_prefixes": [
            "45.55.0.0/16", "64.225.0.0/16", "104.131.0.0/16", "128.199.0.0/16",
            "138.68.0.0/16", "159.65.0.0/16", "162.243.0.0/16", "192.241.0.0/16"
        ]
    },
    # Oracle Cloud
    "Oracle Cloud": {
        "domains": [
            "oraclecloud.com", "oraclecorp.com", "oci.oraclecloud.com"
        ],
        "cnames": [
            r".*\.oraclecloud\.com$"
        ],
        "ip_prefixes": [
            "152.67.0.0/16", "152.70.0.0/16", "192.29.0.0/16", "193.122.0.0/16"
        ]
    },
    # Heroku
    "Heroku": {
        "domains": [
            "herokuapp.com", "herokussl.com", "heroku.com"
        ],
        "cnames": [
            r".*\.herokuapp\.com$",
            r".*\.herokussl\.com$"
        ],
        "ip_prefixes": [
            "50.16.0.0/15", "50.19.0.0/16", "54.243.0.0/16", "54.236.0.0/15"
        ]
    },
    # GitHub Pages
    "GitHub Pages": {
        "domains": [
            "github.io", "githubusercontent.com", "github.com"
        ],
        "cnames": [
            r".*\.github\.io$",
            r".*\.githubusercontent\.com$"
        ],
        "ip_prefixes": [
            "185.199.108.0/22", "140.82.112.0/20", "143.55.64.0/20"
        ]
    },
    # Vercel
    "Vercel": {
        "domains": [
            "vercel.app", "now.sh", "vercel.com"
        ],
        "cnames": [
            r".*\.vercel\.app$",
            r".*\.now\.sh$"
        ],
        "ip_prefixes": []
    },
    # Netlify
    "Netlify": {
        "domains": [
            "netlify.app", "netlify.com"
        ],
        "cnames": [
            r".*\.netlify\.app$",
            r".*\.netlify\.com$"
        ],
        "ip_prefixes": [
            "104.198.14.0/24", "104.196.27.0/24", "104.196.26.0/24"
        ]
    },
    # Linode
    "Linode": {
        "domains": [
            "linode.com", "linode-staging.com", "linodeobjects.com"
        ],
        "cnames": [
            r".*\.linodeobjects\.com$"
        ],
        "ip_prefixes": [
            "45.79.0.0/16", "50.116.0.0/16", "66.175.0.0/16", "96.126.96.0/19",
            "139.162.0.0/16", "172.104.0.0/15", "173.255.192.0/18", "192.155.80.0/20"
        ]
    },
    # Vultr
    "Vultr": {
        "domains": [
            "vultr.com", "vultrobjects.com"
        ],
        "cnames": [
            r".*\.vultrobjects\.com$"
        ],
        "ip_prefixes": [
            "45.32.0.0/16", "45.63.0.0/16", "104.238.128.0/18", "108.61.0.0/16",
            "149.28.0.0/16", "207.246.64.0/18"
        ]
    }
}

# DNS record types to check
RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA', 
    'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'HTTPS', 'SVCB', 'DNAME'
]

# Public DNS servers to use for queries
PUBLIC_DNS_SERVERS = [
    '8.8.8.8',        # Google DNS
    '8.8.4.4',        # Google DNS
    '1.1.1.1',        # Cloudflare
    '1.0.0.1',        # Cloudflare
    '9.9.9.9',        # Quad9
    '149.112.112.112',# Quad9
    '208.67.222.222', # OpenDNS
    '208.67.220.220', # OpenDNS
    '64.6.64.6',      # Verisign
    '64.6.65.6'       # Verisign
]

# Global variables for signal handling
interrupted = False
current_progress = 0
total_items = 0

class TimeoutError(Exception):
    """Exception raised when a function times out."""
    pass

@contextmanager
def time_limit(seconds):
    """Context manager for limiting execution time of a function."""
    def signal_handler(signum, frame):
        raise TimeoutError("Function timed out")
    
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

def handle_interrupt(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully"""
    global interrupted
    if not interrupted:
        print(f"\n{Fore.YELLOW}[!] Interrupt received, finishing current tasks... (Ctrl+C again to force quit)")
        interrupted = True
    else:
        print(f"\n{Fore.RED}[!] Forced exit")
        sys.exit(1)

# Register signal handler
signal.signal(signal.SIGINT, handle_interrupt)

class DNSEnumerator:
    def __init__(self, domain, nameservers=None, wordlist=None, threads=10, 
                 timeout=2, output=None, format="json", verbose=False, max_depth=1,
                 rate_limit=0, resolve_ips=False, check_wildcard=True, resume=False,
                 detect_providers=True):
        self.domain = domain.lower()
        self.timeout = timeout
        self.threads = threads
        self.output = output
        self.format = format
        self.verbose = verbose
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.resolve_ips = resolve_ips
        self.check_wildcard = check_wildcard
        self.resume = resume
        self.detect_providers = detect_providers
        
        self.results = {
            "metadata": {
                "domain": domain,
                "scan_date": datetime.now().isoformat(),
                "version": "2.0.0"
            },
            "nameservers": [],
            "records": {},
            "zone_transfer": {"attempted": False, "successful": False, "results": []},
            "subdomains": [],
            "wildcard_detection": {"detected": False, "ips": []},
            "infrastructure": {"related_domains": []},
            "hosting_providers": {"summary": {}, "details": []}
        }
        
        # Maintain a cache for resume capability
        self.cache_file = f".dns_enum_cache_{self.domain.replace('.', '_')}.json"
        
        # Setup resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Use custom nameservers if provided, otherwise use default ones temporarily
        if nameservers:
            self.resolver.nameservers = nameservers
            self.nameservers = nameservers
        else:
            # Will be populated during nameserver detection
            self.nameservers = []
            self.resolver.nameservers = random.sample(PUBLIC_DNS_SERVERS, 3)
        
        # Get wordlist path
        self.wordlist_path = self._get_wordlist_path(wordlist)
        
        # For wildcard detection
        self.wildcard_ips = set()
        self.has_wildcard = False
        
        # For tracking processed subdomains
        self.processed_subdomains = set()
        
    def _get_wordlist_path(self, wordlist):
        """Get the path to the wordlist file"""
        if not wordlist:
            return None
        
        # If it's a URL from our predefined list, download it
        if wordlist in WORDLIST_PATHS:
            url = WORDLIST_PATHS[wordlist]
            wordlist_dir = os.path.join(os.path.expanduser("~"), ".dns_enum", "wordlists")
            os.makedirs(wordlist_dir, exist_ok=True)
            
            local_path = os.path.join(wordlist_dir, f"{wordlist}.txt")
            
            # Download if not exists
            if not os.path.exists(local_path):
                print(f"{Fore.YELLOW}[*] Downloading wordlist {wordlist}...")
                try:
                    response = requests.get(url)
                    with open(local_path, 'wb') as f:
                        f.write(response.content)
                    print(f"{Fore.GREEN}[+] Wordlist downloaded to {local_path}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Failed to download wordlist: {e}")
                    return None
            
            return local_path
        
        # If it's a path to an existing file
        elif os.path.isfile(wordlist):
            return wordlist
        
        # Otherwise, assume it's a built-in name and try to find it
        else:
            print(f"{Fore.RED}[!] Wordlist not found: {wordlist}")
            self._suggest_wordlists()
            return None
    
    def _suggest_wordlists(self):
        """Suggest available wordlists"""
        print(f"{Fore.YELLOW}[*] Available wordlists:")
        print(f"{Fore.YELLOW}    tiny        - Small subset for quick testing")
        print(f"{Fore.YELLOW}    small       - ~3,000 subdomains")
        print(f"{Fore.YELLOW}    medium      - ~5,000 subdomains")
        print(f"{Fore.YELLOW}    large       - ~20,000 subdomains")
        print(f"{Fore.YELLOW}    xl          - ~110,000 subdomains")
        print(f"{Fore.YELLOW}    dns-jhaddix - ~2,000,000 subdomains (very large)")
        print(f"{Fore.YELLOW}    bitquark    - Top 1,000 subdomains")
    
    def _load_cache(self):
        """Load cache from file if it exists"""
        if not self.resume or not os.path.exists(self.cache_file):
            return False
        
        try:
            with open(self.cache_file, 'r') as f:
                cached_data = json.load(f)
                
            if "metadata" in cached_data and "domain" in cached_data["metadata"]:
                if cached_data["metadata"]["domain"] == self.domain:
                    self.results = cached_data
                    self.processed_subdomains = set(s["name"] for s in cached_data["subdomains"])
                    
                    if "wildcard_detection" in cached_data and cached_data["wildcard_detection"]["detected"]:
                        self.has_wildcard = True
                        self.wildcard_ips = set(cached_data["wildcard_detection"]["ips"])
                    
                    print(f"{Fore.GREEN}[+] Loaded cache with {len(self.processed_subdomains)} processed subdomains")
                    return True
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error loading cache: {e}")
        
        return False
    
    def _save_cache(self):
        """Save current results to cache file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Cache saved to {self.cache_file}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error saving cache: {e}")
    
    def detect_nameservers(self):
        """Detect the authoritative nameservers for the domain"""
        if self.resume and self.results["nameservers"]:
            print(f"{Fore.GREEN}[+] Using cached nameservers")
            self.nameservers = [ns["ip"] for ns in self.results["nameservers"]]
            self.resolver.nameservers = self.nameservers
            return self.nameservers
        
        print(f"{Fore.BLUE}[*] Detecting nameservers for {self.domain}...")
        
        try:
            # First try to get NS records directly
            self.resolver.nameservers = random.sample(PUBLIC_DNS_SERVERS, 3)  # Use 3 random public DNS servers
            ns_records = self.resolver.resolve(self.domain, 'NS')
            nameservers = []
            
            for record in ns_records:
                ns_hostname = str(record.target).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_hostname)
                    nameservers.append(ns_ip)
                    self.results["nameservers"].append({
                        "hostname": ns_hostname,
                        "ip": ns_ip
                    })
                    print(f"{Fore.GREEN}[+] Found nameserver: {ns_hostname} ({ns_ip})")
                except socket.gaierror:
                    print(f"{Fore.YELLOW}[!] Could not resolve IP for nameserver: {ns_hostname}")
            
            if nameservers:
                self.nameservers = nameservers
                self.resolver.nameservers = nameservers
                return nameservers
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error detecting nameservers: {e}")
        
        print(f"{Fore.YELLOW}[!] Using public DNS servers")
        self.nameservers = random.sample(PUBLIC_DNS_SERVERS, 3)
        self.resolver.nameservers = self.nameservers
        return self.nameservers
    
    def detect_wildcard_dns(self):
        """Detect if the domain has wildcard DNS enabled"""
        if self.resume and "wildcard_detection" in self.results:
            if self.results["wildcard_detection"]["detected"]:
                self.has_wildcard = True
                self.wildcard_ips = set(self.results["wildcard_detection"]["ips"])
                print(f"{Fore.YELLOW}[!] Wildcard DNS detected (cached) with IPs: {', '.join(self.wildcard_ips)}")
            return self.has_wildcard
        
        if not self.check_wildcard:
            return False
            
        print(f"{Fore.BLUE}[*] Checking for wildcard DNS...")
        
        # Generate some random subdomains to test
        random_subdomains = [
            f"wildcard-check-{random.randint(100000, 999999)}.{self.domain}" 
            for _ in range(3)
        ]
        
        wildcard_responses = []
        
        for subdomain in random_subdomains:
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                for answer in answers:
                    wildcard_responses.append(str(answer))
            except:
                continue
        
        if wildcard_responses:
            self.has_wildcard = True
            self.wildcard_ips = set(wildcard_responses)
            
            self.results["wildcard_detection"] = {
                "detected": True,
                "ips": list(self.wildcard_ips)
            }
            
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected with IPs: {', '.join(self.wildcard_ips)}")
        else:
            self.results["wildcard_detection"] = {
                "detected": False,
                "ips": []
            }
            print(f"{Fore.GREEN}[+] No wildcard DNS detected")
        
        return self.has_wildcard
    
    def enumerate_records(self):
        """Enumerate all DNS records for the domain"""
        if self.resume and self.results["records"]:
            print(f"{Fore.GREEN}[+] Using cached DNS records")
            return
            
        print(f"{Fore.BLUE}[*] Enumerating DNS records for {self.domain}...")
        
        for record_type in RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                self.results["records"][record_type] = []
                
                for answer in answers:
                    if record_type == 'SOA':
                        data = {
                            "mname": str(answer.mname),
                            "rname": str(answer.rname),
                            "serial": answer.serial,
                            "refresh": answer.refresh,
                            "retry": answer.retry,
                            "expire": answer.expire,
                            "minimum": answer.minimum
                        }
                    elif record_type == 'MX':
                        data = {
                            "preference": answer.preference,
                            "exchange": str(answer.exchange)
                        }
                    elif record_type in ['NS', 'CNAME', 'PTR', 'DNAME']:
                        data = str(answer.target)
                    elif record_type == 'SRV':
                        data = {
                            "priority": answer.priority,
                            "weight": answer.weight,
                            "port": answer.port,
                            "target": str(answer.target)
                        }
                    elif record_type == 'TXT':
                        data = str(answer).strip('"')
                    elif record_type in ['HTTPS', 'SVCB']:
                        # Handle newer record types
                        data = {
                            "priority": answer.priority,
                            "target": str(answer.target),
                            "params": {str(k): str(v) for k, v in answer.params.items()}
                        }
                    else:
                        data = str(answer)
                    
                    self.results["records"][record_type].append(data)
                
                record_count = len(self.results["records"][record_type])
                print(f"{Fore.GREEN}[+] Found {record_count} {record_type} record(s)")
                
                if self.verbose:
                    for i, data in enumerate(self.results["records"][record_type]):
                        print(f"{Fore.GREEN}    {i+1}. {data}")
            
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoNameservers:
                continue
            except dns.exception.Timeout:
                continue
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error querying {record_type} records: {e}")
    
    def attempt_zone_transfer(self):
        """Attempt zone transfer against each nameserver"""
        if self.resume and self.results["zone_transfer"]["attempted"]:
            if self.results["zone_transfer"]["successful"]:
                print(f"{Fore.GREEN}[+] Zone transfer was previously successful")
            return
            
        print(f"{Fore.BLUE}[*] Attempting zone transfer...")
        self.results["zone_transfer"]["attempted"] = True
        
        if not self.nameservers:
            print(f"{Fore.YELLOW}[!] No nameservers to try zone transfer against")
            return
        
        for ns_data in self.results["nameservers"]:
            ns_hostname = ns_data["hostname"]
            ns_ip = ns_data["ip"]
            
            print(f"{Fore.YELLOW}[*] Trying zone transfer from {ns_hostname} ({ns_ip})...")
            
            try:
                # Attempt zone transfer with timeout
                with time_limit(self.timeout * 2):
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=self.timeout))
                
                # If we get here, zone transfer was successful
                self.results["zone_transfer"]["successful"] = True
                print(f"{Fore.GREEN}[+] Zone transfer successful from {ns_hostname}!")
                
                # Extract and store records
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            record = {
                                "name": str(name),
                                "type": rdtype,
                                "data": str(rdata)
                            }
                            self.results["zone_transfer"]["results"].append(record)
                            
                            # Add subdomains from zone transfer
                            if rdtype in ['A', 'AAAA'] and name != '@':
                                fqdn = f"{name}.{self.domain}" if str(name) != '@' else self.domain
                                self.processed_subdomains.add(fqdn)
                                self.results["subdomains"].append({
                                    "name": fqdn,
                                    "ips": [str(rdata)],
                                    "source": "zone_transfer"
                                })
                            
                            if self.verbose:
                                print(f"{Fore.GREEN}    {record['name']} {record['type']} {record['data']}")
                
                # Report success
                count = len(self.results["zone_transfer"]["results"])
                print(f"{Fore.GREEN}[+] Retrieved {count} records via zone transfer")
                
                # Save cache after successful zone transfer
                self._save_cache()
                
                # Usually if one nameserver allows transfer, others will too
                # So we can break here
                break
                
            except TimeoutError:
                print(f"{Fore.RED}[!] Zone transfer timed out for {ns_hostname}")
            except dns.exception.FormError:
                print(f"{Fore.RED}[!] Zone transfer refused by {ns_hostname}")
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error attempting zone transfer from {ns_hostname}: {e}")
    
    def _subdomain_generator(self, wordlist_path):
        """Generate subdomains from wordlist line by line to save memory"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and not subdomain.startswith('#'):
                        yield subdomain
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading wordlist: {e}")
    
    def _count_wordlist_lines(self, wordlist_path):
        """Count the number of lines in the wordlist file"""
        count = 0
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip() and not line.strip().startswith('#'):
                        count += 1
        except Exception as e:
            print(f"{Fore.RED}[!] Error counting wordlist lines: {e}")
        return count
    
    def bruteforce_subdomains(self):
        """Bruteforce subdomains using the provided wordlist"""
        if not self.wordlist_path:
            print(f"{Fore.YELLOW}[!] No wordlist provided for subdomain bruteforcing")
            return
        
        # If we've already found subdomains via zone transfer, ask if we should continue
        if self.results["zone_transfer"]["successful"] and len(self.results["subdomains"]) > 0:
            print(f"{Fore.YELLOW}[!] Zone transfer was successful. Do you still want to bruteforce subdomains? (y/n)")
            answer = input().lower()
            if answer != 'y':
                print(f"{Fore.YELLOW}[*] Skipping subdomain bruteforce")
                return
        
        # Count total subdomains to process
        print(f"{Fore.BLUE}[*] Counting subdomains in wordlist...")
        total_subdomains = self._count_wordlist_lines(self.wordlist_path)
        print(f"{Fore.BLUE}[*] Bruteforcing {total_subdomains} subdomains...")
        
        # Set global variables for signal handling
        global total_items, current_progress
        total_items = total_subdomains
        current_progress = 0
        
        # Process subdomains in chunks to avoid memory issues
        chunk_size = min(1000, max(100, self.threads * 10))
        found_subdomains = []
        
        subdomain_generator = self._subdomain_generator(self.wordlist_path)
        
        with tqdm(total=total_subdomains, desc="Bruteforcing subdomains") as pbar:
            while True:
                current_chunk = []
                chunk_count = 0
                
                # Get the next chunk
                while chunk_count < chunk_size:
                    try:
                        subdomain = next(subdomain_generator)
                        fqdn = f"{subdomain}.{self.domain}"
                        
                        # Skip if already processed
                        if fqdn in self.processed_subdomains:
                            pbar.update(1)
                            current_progress += 1
                            continue
                            
                        current_chunk.append(subdomain)
                        chunk_count += 1
                    except StopIteration:
                        break
                
                # If no more subdomains, we're done
                if not current_chunk:
                    break
                
                # Rate limiting if specified
                if self.rate_limit > 0:
                    delay = 1.0 / (self.rate_limit / len(current_chunk))
                    time.sleep(delay)
                
                # Process this chunk with ThreadPoolExecutor
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_subdomain = {
                        executor.submit(self._check_subdomain, subdomain): subdomain 
                        for subdomain in current_chunk
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_subdomain):
                        subdomain = future_to_subdomain[future]
                        fqdn = f"{subdomain}.{self.domain}"
                        self.processed_subdomains.add(fqdn)
                        pbar.update(1)
                        current_progress += 1
                        
                        try:
                            result = future.result()
                            if result:
                                found_subdomains.append(result)
                                if self.verbose:
                                    ip_str = ", ".join(result.get("ips", []))
                                    print(f"{Fore.GREEN}[+] Found: {result['name']} - {ip_str}")
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.RED}[!] Error checking {fqdn}: {e}")
                
                # Add results to the main data structure
                for subdomain in found_subdomains:
                    if subdomain not in self.results["subdomains"]:
                        subdomain["source"] = "bruteforce"
                        self.results["subdomains"].append(subdomain)
                
                # Reset temp list to save memory
                found_subdomains = []
                
                # Save cache periodically
                if current_progress % 10000 == 0:
                    self._save_cache()
                
                # Check if we were interrupted
                if interrupted:
                    print(f"{Fore.YELLOW}[!] Subdomain bruteforce interrupted")
                    break
        
        print(f"{Fore.GREEN}[+] Found {len(self.results['subdomains'])} subdomains")
    
    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        fqdn = f"{subdomain}.{self.domain}"
        
        try:
            answers = self.resolver.resolve(fqdn, 'A')
            ips = [str(answer) for answer in answers]
            
            # Skip if this matches wildcard DNS
            if self.has_wildcard and set(ips).issubset(self.wildcard_ips):
                return None
            
            # Try to get CNAME if available
            cname = None
            try:
                cname_answers = self.resolver.resolve(fqdn, 'CNAME')
                cname = str(cname_answers[0].target)
            except:
                pass
            
            # Get additional record types if verbose
            extra_records = {}
            if self.verbose:
                for record_type in ['TXT', 'MX', 'NS']:
                    try:
                        record_answers = self.resolver.resolve(fqdn, record_type)
                        extra_records[record_type] = [str(r) for r in record_answers]
                    except:
                        pass
            
            # Detect hosting provider if enabled
            provider = None
            if self.detect_providers:
                provider = self._detect_provider(fqdn, ips, cname)
            
            result = {
                "name": fqdn,
                "ips": ips,
                "cname": cname,
                "records": extra_records
            }
            
            if provider:
                result["provider"] = provider
                
            return result
        except:
            return None
            
    def _detect_provider(self, hostname, ips, cname):
        """Detect hosting provider based on domain, CNAME, and IP addresses"""
        provider_matches = {}
        
        # Check against domain patterns
        for provider_name, provider_data in CLOUD_PROVIDERS.items():
            score = 0
            matched_criteria = []
            
            # Check domain patterns
            if any(pattern in hostname for pattern in provider_data["domains"]):
                score += 3
                matched_criteria.append("domain")
            
            # Check CNAME patterns
            if cname:
                for pattern in provider_data["cnames"]:
                    if re.match(pattern, cname):
                        score += 5
                        matched_criteria.append("cname")
                        break
            
            # Check IP ranges
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    for ip_range in provider_data["ip_prefixes"]:
                        if ip_obj in ipaddress.ip_network(ip_range):
                            score += 4
                            matched_criteria.append("ip_range")
                            break
                except:
                    continue
            
            if score > 0:
                provider_matches[provider_name] = {
                    "score": score,
                    "matched_criteria": list(set(matched_criteria))
                }
        
        # Get the provider with the highest score
        if provider_matches:
            top_provider = max(provider_matches.items(), key=lambda x: x[1]["score"])
            return {
                "name": top_provider[0],
                "confidence": min(100, top_provider[1]["score"] * 20),
                "matched_criteria": top_provider[1]["matched_criteria"]
            }
        
        return None
    
    def analyze_infrastructure(self):
        """Analyze DNS infrastructure for patterns and related domains"""
        print(f"{Fore.BLUE}[*] Analyzing DNS infrastructure...")
        
        # Skip if no subdomains were found
        if not self.results["subdomains"]:
            print(f"{Fore.YELLOW}[!] No subdomains found to analyze")
            return
        
        # Analyze nameserver patterns
        nameserver_domains = set()
        for ns in self.results["nameservers"]:
            ns_hostname = ns["hostname"]
            
            # Extract domain part from nameserver hostname
            parts = ns_hostname.split('.')
            if len(parts) >= 2:
                ns_domain = '.'.join(parts[-2:])
                nameserver_domains.add(ns_domain)
        
        self.results["infrastructure"]["nameserver_domains"] = list(nameserver_domains)
        
        # Analyze IP patterns from subdomains
        ip_groups = {}
        for subdomain in self.results["subdomains"]:
            for ip in subdomain.get("ips", []):
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(subdomain["name"])
        
        self.results["infrastructure"]["ip_groups"] = [
            {"ip": ip, "domains": domains} 
            for ip, domains in ip_groups.items() if len(domains) > 1
        ]
        
        # Report findings
        if nameserver_domains:
            print(f"{Fore.GREEN}[+] Nameserver domains: {', '.join(nameserver_domains)}")
        
        shared_ips = len([g for g in ip_groups.values() if len(g) > 1])
        if shared_ips:
            print(f"{Fore.GREEN}[+] Found {shared_ips} IP addresses hosting multiple subdomains")
            
            if self.verbose:
                for ip, domains in ip_groups.items():
                    if len(domains) > 1:
                        print(f"{Fore.GREEN}    {ip}: {len(domains)} domains")
        
        # Analyze hosting providers if enabled
        if self.detect_providers:
            self._analyze_hosting_providers()
    
    def reverse_lookup_ips(self):
        """Perform reverse DNS lookups on discovered IPs"""
        if not self.resolve_ips:
            return
            
        print(f"{Fore.BLUE}[*] Performing reverse DNS lookups...")
        
        unique_ips = set()
        for subdomain in self.results["subdomains"]:
            for ip in subdomain.get("ips", []):
                unique_ips.add(ip)
        
        if not unique_ips:
            print(f"{Fore.YELLOW}[!] No IPs found to perform reverse lookups")
            return
        
        print(f"{Fore.YELLOW}[*] Looking up {len(unique_ips)} unique IPs...")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {
                executor.submit(self._reverse_lookup, ip): ip for ip in unique_ips
            }
            
            for future in tqdm(concurrent.futures.as_completed(future_to_ip), total=len(unique_ips), desc="Reverse Lookups"):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] {ip} -> {result['hostname']}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error looking up {ip}: {e}")
        
        self.results["infrastructure"]["reverse_lookups"] = results
        
        # Find potential new domains from reverse lookups
        new_domains = set()
        for result in results:
            hostname = result.get("hostname", "")
            if hostname and self.domain not in hostname:
                domain_parts = hostname.split('.')
                if len(domain_parts) >= 2:
                    domain = '.'.join(domain_parts[-2:])
                    if domain != self.domain:
                        new_domains.add(domain)
        
        if new_domains:
            self.results["infrastructure"]["related_domains"] = list(new_domains)
            print(f"{Fore.GREEN}[+] Found {len(new_domains)} potentially related domains")
            
            if self.verbose:
                for domain in new_domains:
                    print(f"{Fore.GREEN}    {domain}")
    
    def _reverse_lookup(self, ip):
        """Perform reverse DNS lookup for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                "ip": ip,
                "hostname": hostname
            }
        except:
            return None
    
    def save_results(self):
        """Save results to the specified output file"""
        if not self.output:
            return
        
        output_path = Path(self.output)
        
        # Create directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save in the specified format
        if self.format == "json" or output_path.suffix == '.json':
            self._save_json(output_path)
        elif self.format == "csv" or output_path.suffix == '.csv':
            self._save_csv(output_path)
        else:
            # Default to text format
            self._save_text(output_path)
    
    def _save_json(self, output_path):
        """Save results in JSON format"""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {output_path} (JSON format)")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results to JSON: {e}")
    
    def _save_csv(self, output_path):
        """Save subdomain results in CSV format"""
        try:
            # Export subdomains to CSV
            subdomains_csv = output_path.with_suffix('.subdomains.csv')
            
            with open(subdomains_csv, 'w', newline='') as f:
                writer = csv.writer(f)
                headers = ['Subdomain', 'IP Addresses', 'CNAME', 'Source']
                
                # Add provider header if detection is enabled
                if self.detect_providers:
                    headers.extend(['Provider', 'Confidence', 'Matched Criteria'])
                
                writer.writerow(headers)
                
                for subdomain in self.results["subdomains"]:
                    row = [
                        subdomain.get("name", ""),
                        ', '.join(subdomain.get("ips", [])),
                        subdomain.get("cname", ""),
                        subdomain.get("source", "unknown")
                    ]
                    
                    # Add provider information if available
                    if self.detect_providers and "provider" in subdomain:
                        row.extend([
                            subdomain["provider"]["name"],
                            f"{subdomain['provider']['confidence']}%",
                            ', '.join(subdomain["provider"]["matched_criteria"])
                        ])
                    elif self.detect_providers:
                        row.extend(["Unknown", "0%", ""])
                    
                    writer.writerow(row)
            
            # Export nameservers to CSV
            nameservers_csv = output_path.with_suffix('.nameservers.csv')
            with open(nameservers_csv, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Hostname', 'IP'])
                
                for ns in self.results["nameservers"]:
                    writer.writerow([ns.get("hostname", ""), ns.get("ip", "")])
            
            # Export provider summary if detection is enabled
            if self.detect_providers and self.results["hosting_providers"]["summary"]:
                providers_csv = output_path.with_suffix('.providers.csv')
                with open(providers_csv, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Provider', 'Subdomain Count', 'Percentage'])
                    
                    for provider in self.results["hosting_providers"]["summary"]:
                        percentage = (provider["count"] / len(self.results["subdomains"])) * 100
                        writer.writerow([
                            provider["provider"],
                            provider["count"],
                            f"{percentage:.1f}%"
                        ])
                
                print(f"{Fore.GREEN}[+] Provider summary saved to {providers_csv}")
            
            print(f"{Fore.GREEN}[+] Subdomain results saved to {subdomains_csv}")
            print(f"{Fore.GREEN}[+] Nameserver results saved to {nameservers_csv}")
            
            # If pandas is available, create an Excel file with multiple sheets
            if PANDAS_AVAILABLE:
                try:
                    excel_path = output_path.with_suffix('.xlsx')
                    
                    # Create DataFrames
                    subdomain_data = []
                    for s in self.results["subdomains"]:
                        data = {
                            'Subdomain': s.get("name", ""),
                            'IP Addresses': ', '.join(s.get("ips", [])),
                            'CNAME': s.get("cname", ""),
                            'Source': s.get("source", "unknown")
                        }
                        
                        # Add provider information if available
                        if self.detect_providers and "provider" in s:
                            data.update({
                                'Provider': s["provider"]["name"],
                                'Confidence': f"{s['provider']['confidence']}%",
                                'Matched Criteria': ', '.join(s["provider"]["matched_criteria"])
                            })
                        
                        subdomain_data.append(data)
                    
                    subdomains_df = pd.DataFrame(subdomain_data)
                    
                    nameservers_df = pd.DataFrame([
                        {'Hostname': ns.get("hostname", ""), 'IP': ns.get("ip", "")}
                        for ns in self.results["nameservers"]
                    ])
                    
                    # Create records DataFrame
                    records_data = []
                    for record_type, records in self.results["records"].items():
                        for record in records:
                            if isinstance(record, dict):
                                record_str = json.dumps(record)
                            else:
                                record_str = str(record)
                            
                            records_data.append({
                                'Type': record_type,
                                'Value': record_str
                            })
                    
                    records_df = pd.DataFrame(records_data)
                    
                    # Create providers DataFrame if available
                    if self.detect_providers and self.results["hosting_providers"]["summary"]:
                        providers_data = []
                        for provider in self.results["hosting_providers"]["summary"]:
                            percentage = (provider["count"] / len(self.results["subdomains"])) * 100
                            providers_data.append({
                                'Provider': provider["provider"],
                                'Count': provider["count"],
                                'Percentage': f"{percentage:.1f}%"
                            })
                        
                        providers_df = pd.DataFrame(providers_data)
                    
                    # Write to Excel
                    with pd.ExcelWriter(excel_path) as writer:
                        subdomains_df.to_excel(writer, sheet_name="Subdomains", index=False)
                        nameservers_df.to_excel(writer, sheet_name="Nameservers", index=False)
                        records_df.to_excel(writer, sheet_name="Records", index=False)
                        
                        if self.detect_providers and self.results["hosting_providers"]["summary"]:
                            providers_df.to_excel(writer, sheet_name="Providers", index=False)
                    
                    print(f"{Fore.GREEN}[+] Comprehensive results saved to {excel_path}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error creating Excel file: {e}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results to CSV: {e}")
    
    def _save_text(self, output_path):
        """Save results in text format"""
        try:
            with open(output_path, 'w') as f:
                f.write(f"DNS Enumeration Results for {self.domain}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Write nameservers
                f.write("=== NAMESERVERS ===\n")
                for ns in self.results["nameservers"]:
                    f.write(f"{ns['hostname']} ({ns['ip']})\n")
                
                # Write main domain records
                f.write("\n=== DNS RECORDS ===\n")
                for record_type, records in self.results["records"].items():
                    f.write(f"\n{record_type} Records:\n")
                    for record in records:
                        if isinstance(record, dict):
                            for k, v in record.items():
                                f.write(f"  {k}: {v}\n")
                            f.write("\n")
                        else:
                            f.write(f"  {record}\n")
                
                # Write zone transfer results
                f.write("\n=== ZONE TRANSFER ===\n")
                if self.results["zone_transfer"]["successful"]:
                    f.write("Zone transfer was SUCCESSFUL\n")
                    f.write(f"Retrieved {len(self.results['zone_transfer']['results'])} records\n")
                else:
                    f.write("Zone transfer was not successful\n")
                
                # Write wildcard detection
                f.write("\n=== WILDCARD DETECTION ===\n")
                if self.results["wildcard_detection"]["detected"]:
                    f.write(f"Wildcard DNS detected with IPs: {', '.join(self.results['wildcard_detection']['ips'])}\n")
                else:
                    f.write("No wildcard DNS detected\n")
                
                # Write subdomains
                f.write(f"\n=== SUBDOMAINS ({len(self.results['subdomains'])}) ===\n")
                for subdomain in sorted(self.results["subdomains"], key=lambda x: x["name"]):
                    f.write(f"{subdomain['name']}\n")
                    f.write(f"  IP(s): {', '.join(subdomain.get('ips', []))}\n")
                    if subdomain.get("cname"):
                        f.write(f"  CNAME: {subdomain['cname']}\n")
                    if subdomain.get("provider"):
                        f.write(f"  Provider: {subdomain['provider']['name']} (Confidence: {subdomain['provider']['confidence']}%)\n")
                    f.write(f"  Source: {subdomain.get('source', 'unknown')}\n")
                    f.write("\n")
                
                # Write infrastructure analysis
                f.write("\n=== INFRASTRUCTURE ANALYSIS ===\n")
                if "nameserver_domains" in self.results["infrastructure"]:
                    f.write(f"Nameserver Domains: {', '.join(self.results['infrastructure']['nameserver_domains'])}\n")
                
                if "related_domains" in self.results["infrastructure"]:
                    f.write(f"\nRelated Domains: {', '.join(self.results['infrastructure']['related_domains'])}\n")
                
                if "ip_groups" in self.results["infrastructure"]:
                    f.write("\nShared IP Addresses:\n")
                    for group in self.results["infrastructure"]["ip_groups"]:
                        f.write(f"  {group['ip']} hosts {len(group['domains'])} domains\n")
                
                # Write hosting provider information
                if self.detect_providers and self.results["hosting_providers"]["summary"]:
                    f.write("\n=== HOSTING PROVIDERS ===\n")
                    for provider in self.results["hosting_providers"]["summary"]:
                        percentage = (provider["count"] / len(self.results["subdomains"])) * 100
                        f.write(f"{provider['provider']}: {provider['count']} subdomains ({percentage:.1f}%)\n")
                    
                    if self.verbose:
                        f.write("\nDetailed Provider Breakdown:\n")
                        for detail in self.results["hosting_providers"]["details"]:
                            f.write(f"{detail['subdomain']} => {detail['provider']} ")
                            f.write(f"(Confidence: {detail['confidence']}%, ")
                            f.write(f"Matched: {', '.join(detail['criteria'])})\n")
                
            print(f"{Fore.GREEN}[+] Results saved to {output_path} (Text format)")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results to text file: {e}")
    
    def _analyze_hosting_providers(self):
        """Analyze and summarize detected hosting providers"""
        provider_count = {}
        provider_details = []
        
        print(f"{Fore.BLUE}[*] Analyzing hosting provider distribution...")
        
        # Count occurrences of each provider
        for subdomain in self.results["subdomains"]:
            if "provider" in subdomain:
                provider_name = subdomain["provider"]["name"]
                confidence = subdomain["provider"]["confidence"]
                
                if provider_name not in provider_count:
                    provider_count[provider_name] = 0
                
                provider_count[provider_name] += 1
                
                provider_details.append({
                    "subdomain": subdomain["name"],
                    "provider": provider_name,
                    "confidence": confidence,
                    "criteria": subdomain["provider"]["matched_criteria"]
                })
        
        # Sort providers by count
        sorted_providers = sorted(provider_count.items(), key=lambda x: x[1], reverse=True)
        
        # Save to results
        self.results["hosting_providers"]["summary"] = [
            {"provider": provider, "count": count} for provider, count in sorted_providers
        ]
        self.results["hosting_providers"]["details"] = provider_details
        
        # Display results
        if sorted_providers:
            print(f"{Fore.GREEN}[+] Detected {len(sorted_providers)} hosting providers:")
            
            for provider, count in sorted_providers:
                percentage = (count / len(self.results["subdomains"])) * 100
                print(f"{Fore.GREEN}    {provider}: {count} subdomains ({percentage:.1f}%)")
        else:
            print(f"{Fore.YELLOW}[!] No hosting providers detected")
    
    def display_summary(self):
        """Display a summary of the enumeration results"""
        print(f"\n{Fore.BLUE}{'=' * 60}")
        print(f"{Fore.BLUE}DNS Enumeration Summary for {self.domain}")
        print(f"{Fore.BLUE}{'=' * 60}\n")
        
        print(f"{Fore.GREEN}Nameservers: {len(self.results['nameservers'])}")
        print(f"{Fore.GREEN}Subdomains discovered: {len(self.results['subdomains'])}")
        
        record_types = len(self.results["records"])
        total_records = sum(len(records) for records in self.results["records"].values())
        print(f"{Fore.GREEN}Records: {total_records} records across {record_types} types")
        
        if self.results["zone_transfer"]["successful"]:
            print(f"{Fore.GREEN}Zone Transfer: Successful ({len(self.results['zone_transfer']['results'])} records)")
        else:
            print(f"{Fore.RED}Zone Transfer: Failed")
        
        if self.results["wildcard_detection"]["detected"]:
            print(f"{Fore.YELLOW}Wildcard DNS: Detected")
        else:
            print(f"{Fore.GREEN}Wildcard DNS: Not detected")
        
        if "related_domains" in self.results["infrastructure"]:
            print(f"{Fore.GREEN}Related domains: {len(self.results['infrastructure']['related_domains'])}")
        
        # Print provider distribution if available
        if self.detect_providers and "summary" in self.results["hosting_providers"] and self.results["hosting_providers"]["summary"]:
            print(f"\n{Fore.GREEN}Hosting Provider Distribution:")
            for provider in self.results["hosting_providers"]["summary"][:5]:  # Show top 5
                percentage = (provider["count"] / len(self.results["subdomains"])) * 100
                print(f"{Fore.GREEN}    {provider['provider']}: {provider['count']} ({percentage:.1f}%)")
        
        print(f"\n{Fore.BLUE}{'=' * 60}")
    
    def run(self):
        """Run the full DNS enumeration process"""
        print(f"{Fore.BLUE}[*] Starting DNS enumeration for {self.domain}")
        start_time = time.time()
        
        # Try to load from cache if resuming
        cached = self._load_cache() if self.resume else False
        
        # Detect nameservers first
        self.detect_nameservers()
        
        # Check for wildcard DNS
        self.detect_wildcard_dns()
        
        # Enumerate DNS records
        self.enumerate_records()
        
        # Attempt zone transfer
        self.attempt_zone_transfer()
        
        # If zone transfer failed or we want to be thorough, try brute forcing
        if (not self.results["zone_transfer"]["successful"] or len(self.results["subdomains"]) < 10) and self.wordlist_path:
            self.bruteforce_subdomains()
        elif self.results["zone_transfer"]["successful"] and not self.wordlist_path:
            print(f"{Fore.GREEN}[+] Zone transfer was successful, skipping subdomain bruteforce")
        
        # Additional analysis
        if len(self.results["subdomains"]) > 0:
            self.analyze_infrastructure()
            self.reverse_lookup_ips()
        
        # Save final results
        self._save_cache()
        self.save_results()
        
        # Display summary
        self.display_summary()
        
        elapsed_time = time.time() - start_time
        print(f"{Fore.BLUE}[*] DNS enumeration completed in {elapsed_time:.2f} seconds")
        
        # Clean up cache if everything completed successfully
        if not interrupted and self.output:
            try:
                os.remove(self.cache_file)
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Removed cache file {self.cache_file}")
            except:
                pass
                
        # Print provider information about the parent domain
        if self.detect_providers:
            print(f"\n{Fore.BLUE}[*] Analyzing parent domain hosting provider...")
            provider = self._detect_provider(self.domain, 
                                            self.results["records"].get("A", []), 
                                            self.results["records"].get("CNAME", []))
            if provider:
                print(f"{Fore.GREEN}[+] Main domain {self.domain} appears to be hosted on: {provider['name']}")
                print(f"{Fore.GREEN}    Confidence: {provider['confidence']}%")
                print(f"{Fore.GREEN}    Matched criteria: {', '.join(provider['matched_criteria'])}")
            else:
                print(f"{Fore.YELLOW}[!] Could not determine hosting provider for {self.domain}")
                
            # Print most common providers
            if self.results["hosting_providers"]["summary"]:
                print(f"\n{Fore.BLUE}[*] Top hosting providers detected across all subdomains:")
                for idx, provider in enumerate(self.results["hosting_providers"]["summary"][:5]):
                    percentage = (provider["count"] / len(self.results["subdomains"])) * 100
                    print(f"{Fore.GREEN}    {idx+1}. {provider['provider']}: {provider['count']} subdomains ({percentage:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Advanced DNS Enumeration Tool")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("-w", "--wordlist", help="Wordlist for subdomain bruteforcing (or use predefined: tiny, small, medium, large, xl, dns-jhaddix, bitquark)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for subdomain bruteforcing (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json", help="Output format (default: json)")
    parser.add_argument("-n", "--nameserver", action="append", help="Custom nameserver to use (can be specified multiple times)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout for DNS queries in seconds (default: 2.0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-l", "--list-wordlists", action="store_true", help="List available built-in wordlists")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Recursion depth for subdomain discovery (default: 1)")
    parser.add_argument("-r", "--rate-limit", type=int, default=0, help="Rate limit in queries per second (default: unlimited)")
    parser.add_argument("--resolve-ips", action="store_true", help="Perform reverse DNS lookups on discovered IPs")
    parser.add_argument("--no-wildcard-check", action="store_true", help="Skip wildcard DNS detection")
    parser.add_argument("--resume", action="store_true", help="Resume from previous scan if available")
    parser.add_argument("--no-provider-detection", action="store_true", help="Disable cloud provider detection")
    
    args = parser.parse_args()
    
    if args.list_wordlists:
        print(f"{Fore.YELLOW}[*] Available wordlists:")
        for name, url in WORDLIST_PATHS.items():
            print(f"{Fore.YELLOW}    {name}")
        return
    
    enumerator = DNSEnumerator(
        domain=args.domain,
        nameservers=args.nameserver,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        format=args.format,
        verbose=args.verbose,
        max_depth=args.depth,
        rate_limit=args.rate_limit,
        resolve_ips=args.resolve_ips,
        check_wildcard=not args.no_wildcard_check,
        resume=args.resume,
        detect_providers=not args.no_provider_detection
    )
    
    enumerator.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user")
        sys.exit(1)
