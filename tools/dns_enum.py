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
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import html
import jinja2  # For HTML report generation
import string
import textwrap
import traceback
from typing import Dict, List, Optional, Set, Tuple
from rich.console import Console
from rich.progress import Progress
from rich import print as rprint

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.name
    import dns.reversename
    import dns.dnssec
    import dns.flags
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
    # Quick testing wordlists
    "tiny": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "small": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt",
    
    # Standard wordlists
    "medium": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    "large": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
    
    # Comprehensive wordlists
    "xl": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
    "xxl": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/all.txt",
    
    # Specialized wordlists
    "tech": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/tech-subdomains.txt",
    "dev": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dev-subdomains.txt",
    "cloud": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/cloud-subdomains.txt",
    
    # Popular subdomains
    "bitquark": "https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000",
    "commonspeak": "https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt"
}

# Wordlist categories for better organization
WORDLIST_CATEGORIES = {
    "quick": ["tiny", "small"],
    "standard": ["medium", "large"],
    "comprehensive": ["xl", "xxl"],
    "specialized": ["tech", "dev", "cloud"],
    "popular": ["bitquark", "commonspeak"]
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

# SMTP/Email provider signatures
EMAIL_PROVIDERS = {
    "Google Workspace": {
        "mx_patterns": [
            r"aspmx\.l\.google\.com$",
            r"alt[0-9]+\.aspmx\.l\.google\.com$",
            r"smtp-relay\.gmail\.com$"
        ],
        "spf_includes": [
            "include:_spf.google.com",
            "include:_spf.smtp.gmail.com"
        ],
        "dmarc_recommended": "p=reject",
        "additional_records": ["google-site-verification"]
    },
    "Microsoft 365": {
        "mx_patterns": [
            r".*\.mail\.protection\.outlook\.com$",
            r".*\.mail\.onmicrosoft\.com$"
        ],
        "spf_includes": [
            "include:spf.protection.outlook.com"
        ],
        "dmarc_recommended": "p=reject",
        "additional_records": ["MS=ms"]
    },
    "Amazon SES": {
        "mx_patterns": [
            r"inbound-smtp\..*\.amazonaws\.com$"
        ],
        "spf_includes": [
            "include:amazonses.com"
        ],
        "dmarc_recommended": "p=reject",
        "additional_records": []
    },
    "Proofpoint": {
        "mx_patterns": [
            r".*\.pphosted\.com$"
        ],
        "spf_includes": [
            "include:spf.protection.outlook.com"
        ],
        "dmarc_recommended": "p=reject",
        "additional_records": []
    },
    "Mimecast": {
        "mx_patterns": [
            r".*\.mimecast\.com$"
        ],
        "spf_includes": [
            "include:_netblocks.mimecast.com"
        ],
        "dmarc_recommended": "p=reject",
        "additional_records": []
    },
    "Zoho": {
        "mx_patterns": [
            r"mx\.zoho\.com$",
            r"mx[0-9]+\.zoho\.com$"
        ],
        "spf_includes": [
            "include:zoho.com"
        ],
        "dmarc_recommended": "p=reject",
        "additional_records": []
    }
}

# Common SMTP security issues
SMTP_SECURITY_CHECKS = {
    "open_relay": {
        "ports": [25, 587, 465],
        "test_commands": [
            "HELO test.com",
            "MAIL FROM: test@test.com",
            "RCPT TO: test@test.com",
            "DATA",
            "Subject: Test",
            ".",
            "QUIT"
        ]
    },
    "starttls_required": {
        "ports": [25, 587]
    },
    "banner_check": {
        "dangerous_strings": [
            "postfix",
            "exim",
            "sendmail",
            "microsoft smtp server"
        ]
    }
}

# Common subdomain takeover signatures
TAKEOVER_SIGNATURES = {
    "AWS/S3": {
        "signatures": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "S3 Bucket not found"
        ],
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-[a-z0-9-]+\.amazonaws\.com$"
        ]
    },
    "GitHub Pages": {
        "signatures": [
            "There isn't a GitHub Pages site here",
            "404: Not Found",
            "No such app"
        ],
        "cname_patterns": [
            r"\.github\.io$",
            r"\.githubusercontent\.com$"
        ]
    },
    "Heroku": {
        "signatures": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "Nothing to see here",
            "Building a brand new app"
        ],
        "cname_patterns": [
            r"\.herokuapp\.com$",
            r"\.herokudns\.com$"
        ]
    },
    "Fastly": {
        "signatures": [
            "Fastly error: unknown domain",
            "Unknown domain",
            "Fatal Error"
        ],
        "cname_patterns": [
            r"\.fastly\.net$"
        ]
    },
    "Azure": {
        "signatures": [
            "404 Web Site not found",
            "This web app has been stopped",
            "This webpage is not available"
        ],
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.azure-api\.net$"
        ]
    },
    "Zendesk": {
        "signatures": [
            "Help Center Closed",
            "this help center no longer exists",
            "Oops, this help center no longer exists"
        ],
        "cname_patterns": [
            r"\.zendesk\.com$"
        ]
    },
    "Shopify": {
        "signatures": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
            "Sorry, we couldn't find that store"
        ],
        "cname_patterns": [
            r"\.myshopify\.com$"
        ]
    },
    "Squarespace": {
        "signatures": [
            "You're Almost There...",
            "Website Has Expired",
            "This domain is not configured"
        ],
        "cname_patterns": [
            r"\.squarespace\.com$"
        ]
    },
    "Wordpress": {
        "signatures": [
            "Do you want to register",
            "Domain mapping upgrade for this domain not found",
            "This domain is no longer available"
        ],
        "cname_patterns": [
            r"\.wordpress\.com$",
            r"\.wp\.com$"
        ]
    }
}

# Common sensitive files and endpoints to check
SENSITIVE_FILES = {
    "Source Code": [
        "/.git/config",
        "/.env",
        "/.npmrc",
        "/wp-config.php.bak",
        "/.htaccess",
        "/config.php.bak",
        "/database.yml",
        "/.svn/entries",
        "/composer.json",
        "/package.json",
        "/Dockerfile",
        "/docker-compose.yml"
    ],
    "Backups": [
        "/backup.sql",
        "/dump.sql",
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.tgz",
        "/backup.7z",
        "/db.sql",
        "/*.bak",
        "/*.backup",
        "/*.old"
    ],
    "Configuration": [
        "/phpinfo.php",
        "/info.php",
        "/config.php",
        "/configuration.php",
        "/settings.php",
        "/admin/config",
        "/admin/settings",
        "/server-status",
        "/nginx_status",
        "/.well-known/security.txt"
    ],
    "Debug & Logs": [
        "/debug.log",
        "/error.log",
        "/access.log",
        "/debug.php",
        "/console",
        "/logs/",
        "/.DS_Store",
        "/robots.txt",
        "/crossdomain.xml",
        "/sitemap.xml"
    ],
    "API & Documentation": [
        "/api/",
        "/swagger",
        "/swagger-ui.html",
        "/api-docs",
        "/graphql",
        "/graphiql",
        "/docs/",
        "/readme.md",
        "/README.md",
        "/api/v1/",
        "/api/v2/"
    ],
    "Admin & Management": [
        "/admin",
        "/administrator",
        "/admin.php",
        "/wp-admin",
        "/phpmyadmin",
        "/manager",
        "/management",
        "/jenkins",
        "/jmx-console",
        "/server-manager"
    ]
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS enforces secure (HTTPS) connections to the server",
        "recommended": "max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks",
        "recommended": ["DENY", "SAMEORIGIN"]
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and other injection attacks",
        "recommended": "default-src 'self'"
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering",
        "recommended": "1; mode=block"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information should be included",
        "recommended": ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"]
    },
    "Permissions-Policy": {
        "description": "Controls which features and APIs can be used",
        "recommended": "geolocation=(), microphone=()"
    }
}

# DNS record types to check
RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA', 
    'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'HTTPS', 'SVCB', 'DNAME'
]

# DNSSEC record types to check
DNSSEC_RECORD_TYPES = ['DNSKEY', 'DS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'RRSIG']

# DNSSEC algorithm numbers and their meanings
DNSSEC_ALGORITHMS = {
    0: "Delete DS",
    1: "RSA/MD5 (deprecated)",
    2: "Diffie-Hellman",
    3: "DSA/SHA1",
    5: "RSA/SHA-1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "GOST R 34.10-2001",
    13: "ECDSA Curve P-256 with SHA-256",
    14: "ECDSA Curve P-384 with SHA-384",
    15: "Ed25519",
    16: "Ed448"
}

# DNSSEC digest types
DNSSEC_DIGEST_TYPES = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384"
}

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
    
    # Use different timeout mechanisms for Windows vs Unix
    if os.name == 'nt':  # Windows
        import threading
        result = []
        def handler():
            result.append(TimeoutError("Function timed out"))
        timer = threading.Timer(seconds, handler)
        timer.start()
        try:
            yield
        finally:
            timer.cancel()
        if result:
            raise result[0]
    else:  # Unix
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

class DNSEnumerator(BaseTool):
    def __init__(self):
        """Initialize the DNS Enumerator tool"""
        super().__init__(
            name="dns-enum",
            description="Comprehensive DNS enumeration and analysis"
        )
        # Set default values for parameters
        self.domain = None
        self.timeout = 2
        self.threads = 10
        self.output = None
        self.format = "json"
        self.verbose = False
        self.max_depth = 1
        self.rate_limit = 0
        self.resolve_ips = False
        self.check_wildcard = True
        self.resume = False
        self.detect_providers = True
        self.wordlist = None
        self.args = None
        
        # Initialize DNS flags
        self.dnssec_flags = dns.flags.DO | dns.flags.CD
        
        # Initialize resolver with default settings
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        # Initialize results structure
        self.results = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "version": "2.0.0"
            },
            "nameservers": [],
            "records": {},
            "zone_transfer": {"attempted": False, "successful": False, "results": []},
            "subdomains": [],
            "wildcard_detection": {"detected": False, "ips": []},
            "infrastructure": {"related_domains": [], "ptr_records": []},
            "hosting_providers": {"summary": {}, "details": []}
        }

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        super().setup_argparse(parser)
        
        parser.add_argument('domain', help='Target domain to analyze')
        parser.add_argument('-w', '--wordlist', help='Path to wordlist file or predefined wordlist name')
        parser.add_argument('-l', '--list', action='store_true',
                          help='List available wordlists')
        parser.add_argument('-t', '--threads', type=int, default=10,
                          help='Number of threads (default: 10)')
        parser.add_argument('--timeout', type=int, default=2,
                          help='Timeout in seconds (default: 2)')
        parser.add_argument('-r', '--rate-limit', type=int, default=0,
                          help='Rate limit requests per second (default: 0)')
        parser.add_argument('--output-format', choices=['json', 'csv', 'txt', 'html'],
                          default='json', help='Output format')
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Enable verbose output')
        parser.add_argument('-d', '--depth', type=int, default=1,
                          help='Maximum recursion depth')
        parser.add_argument('--resolve-ips', action='store_true',
                          help='Perform reverse DNS lookups')
        parser.add_argument('--no-wildcard-check', action='store_true',
                          help='Skip wildcard detection')
        parser.add_argument('--resume', action='store_true',
                          help='Resume from cached results')
        parser.add_argument('--no-provider-detection', action='store_true',
                          help='Skip cloud provider detection')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
        try:
            # Initialize tool result
            result = ToolResult(
                success=True,
                tool_name=self.name,
                findings=[],
                metadata={}
            )
            
            # Store arguments
            self.args = args
            self.domain = args.domain.lower()
            self.timeout = args.timeout
            self.threads = args.threads
            self.output = args.output
            self.format = args.output_format
            self.verbose = args.verbose
            self.max_depth = args.depth
            self.rate_limit = args.rate_limit
            self.resolve_ips = args.resolve_ips
            self.check_wildcard = not args.no_wildcard_check
            self.resume = args.resume
            self.detect_providers = not args.no_provider_detection
            self.wordlist = args.wordlist if hasattr(args, 'wordlist') else None
            
            # Configure resolver with updated timeout
            self.resolver.timeout = self.timeout
            self.resolver.lifetime = self.timeout
            
            # Update metadata
            self.results["metadata"].update({
                "domain": self.domain,
                "scan_time": datetime.now().isoformat(),
                "arguments": {
                    "timeout": self.timeout,
                    "threads": self.threads,
                    "resolve_ips": self.resolve_ips,
                    "check_wildcard": self.check_wildcard,
                    "detect_providers": self.detect_providers,
                    "max_depth": self.max_depth
                }
            })
            
            # If listing wordlists was requested
            if hasattr(args, 'list') and args.list:
                self._list_wordlists()
                result.metadata["action"] = "list_wordlists"
                return result
            
            # Run enumeration
            self.run_enumeration()
            
            # Process results and add findings
            self._process_results(result)
            
            # Save results if output file specified
            if self.output:
                self._save_results(self.output, self.format)
            
            return result
            
        except Exception as e:
            error_msg = f"Error during DNS enumeration: {str(e)}"
            if self.framework_mode:
                self.logger.error(error_msg)
                if self.verbose:
                    self.logger.debug(traceback.format_exc())
            else:
                print(f"[!] {error_msg}")
                if self.verbose:
                    print(traceback.format_exc())
            
            result.success = False
            result.add_error(error_msg)
            return result

    def _process_results(self, result: ToolResult):
        """Process results and add findings to the tool result"""
        # Add nameserver findings
        for ns in self.results["nameservers"]:
            result.add_finding(
                title=f"Nameserver found: {ns['hostname']}",
                description=f"IP: {ns['ip']}",
                risk_level="Info",
                evidence=f"Hostname: {ns['hostname']}\nIP: {ns['ip']}"
            )
        
        # Add zone transfer findings
        if self.results["zone_transfer"]["successful"]:
            result.add_finding(
                title="Zone transfer successful",
                description="Zone transfer was successful - this is a security risk",
                risk_level="High",
                evidence=f"Records obtained: {len(self.results['zone_transfer']['results'])}"
            )
        
        # Add wildcard detection findings
        if self.results["wildcard_detection"]["detected"]:
            result.add_finding(
                title="Wildcard DNS detected",
                description="Wildcard DNS can make subdomain enumeration more difficult",
                risk_level="Info",
                evidence=f"Wildcard IPs: {', '.join(self.results['wildcard_detection']['ips'])}"
            )
        
        # Add subdomain findings
        for subdomain in self.results["subdomains"]:
            result.add_finding(
                title=f"Subdomain found: {subdomain['name']}",
                description=f"IPs: {', '.join(subdomain.get('ips', []))}",
                risk_level="Info",
                evidence=json.dumps(subdomain, indent=2)
            )
            
        # Add cloud provider findings
        for provider, count in self.results["hosting_providers"]["summary"].items():
            evidence = self.results["hosting_providers"]["details"].get(provider, [])
            evidence_str = json.dumps(evidence, indent=2) if evidence else "No detailed evidence available"
            
            result.add_finding(
                title=f"Cloud provider detected: {provider}",
                description=f"Found {count} instances of {provider} usage",
                risk_level="Info",
                evidence=evidence_str
            )
        
        # Add raw results to metadata
        result.metadata.update(self.results)

    def _save_results(self, output_file: str, format: str):
        """Save results to file in specified format"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(self.results, f, indent=4)
            elif format == 'csv':
                self._save_csv(output_path)
            elif format == 'html':
                self._save_html(output_path)
            elif format == 'txt':
                self._save_txt(output_path)
                
            message = f"Results saved to {output_file}"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[+] {message}")
                
        except Exception as e:
            error_msg = f"Error saving results: {str(e)}"
            if self.framework_mode:
                self.logger.error(error_msg)
            else:
                print(f"[!] {error_msg}")

    def _save_csv(self, output_path: Path):
        """Save results in CSV format"""
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Name', 'Value'])
            
            # Write nameservers
            for ns in self.results["nameservers"]:
                writer.writerow(['Nameserver', ns['hostname'], ns['ip']])
            
            # Write DNS records
            for record_type, records in self.results["records"].items():
                for record in records:
                    writer.writerow(['DNS Record', record_type, record])
            
            # Write subdomains
            for subdomain in self.results["subdomains"]:
                writer.writerow(['Subdomain', subdomain['name'], 
                               ', '.join(subdomain.get('ips', []))])

    def _save_html(self, output_path: Path):
        """Save results in HTML format"""
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>DNS Enumeration Results - {{ domain }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; }
                .finding { border-left: 5px solid #ddd; padding: 10px; margin: 10px 0; }
                .Critical { border-left-color: #ff0000; }
                .High { border-left-color: #ff6600; }
                .Medium { border-left-color: #ffcc00; }
                .Low { border-left-color: #00cc00; }
                .Info { border-left-color: #0066cc; }
            </style>
        </head>
        <body>
            <h1>DNS Enumeration Results for {{ domain }}</h1>
            <div class="section">
                <h2>Nameservers</h2>
                {% for ns in nameservers %}
                <div class="finding Info">
                    <h3>{{ ns.hostname }}</h3>
                    <p>IP: {{ ns.ip }}</p>
                </div>
                {% endfor %}
            </div>
            
            <div class="section">
                <h2>DNS Records</h2>
                {% for type, records in dns_records.items() %}
                <h3>{{ type }} Records</h3>
                <ul>
                {% for record in records %}
                    <li>{{ record }}</li>
                {% endfor %}
                </ul>
                {% endfor %}
            </div>
            
            <div class="section">
                <h2>Subdomains</h2>
                {% for subdomain in subdomains %}
                <div class="finding Info">
                    <h3>{{ subdomain.name }}</h3>
                    <p>IPs: {{ subdomain.ips|join(', ') }}</p>
                </div>
                {% endfor %}
            </div>
            
            {% if hosting_providers.summary %}
            <div class="section">
                <h2>Cloud Providers</h2>
                {% for provider, count in hosting_providers.summary.items() %}
                <div class="finding Info">
                    <h3>{{ provider }}</h3>
                    <p>Instances: {{ count }}</p>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </body>
        </html>
        """
        
        template = jinja2.Template(template_str)
        html_content = template.render(
            domain=self.domain,
            nameservers=self.results["nameservers"],
            dns_records=self.results["records"],
            subdomains=self.results["subdomains"],
            hosting_providers=self.results["hosting_providers"]
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)

    def _save_txt(self, output_path: Path):
        """Save results in text format"""
        with open(output_path, 'w') as f:
            f.write(f"DNS Enumeration Results for {self.domain}\n")
            f.write("=" * 50 + "\n\n")
            
            # Write nameservers
            f.write("Nameservers:\n")
            f.write("-" * 20 + "\n")
            for ns in self.results["nameservers"]:
                f.write(f"{ns['hostname']} ({ns['ip']})\n")
            f.write("\n")
            
            # Write DNS records
            f.write("DNS Records:\n")
            f.write("-" * 20 + "\n")
            for record_type, records in self.results["records"].items():
                f.write(f"\n{record_type} Records:\n")
                for record in records:
                    f.write(f"  {record}\n")
            f.write("\n")
            
            # Write subdomains
            f.write("Subdomains:\n")
            f.write("-" * 20 + "\n")
            for subdomain in self.results["subdomains"]:
                f.write(f"{subdomain['name']}\n")
                if 'ips' in subdomain:
                    f.write(f"  IPs: {', '.join(subdomain['ips'])}\n")
            f.write("\n")
            
            # Write cloud providers
            if self.results["hosting_providers"]["summary"]:
                f.write("Cloud Providers:\n")
                f.write("-" * 20 + "\n")
                for provider, count in self.results["hosting_providers"]["summary"].items():
                    f.write(f"{provider}: {count} instances\n")

def main():
    """Main entry point for the tool"""
    try:
        tool = DNSEnumerator()
        parser = argparse.ArgumentParser(description=tool.description)
        tool.setup_argparse(parser)
        args = parser.parse_args()
        
        result = tool.run(args)
        
        if isinstance(result, ToolResult):
            return {
                'status': 'success' if result.success else 'error',
                'findings': result.findings,
                'risk_summary': result.risk_summary,
                'metadata': result.metadata
            }
        return {'status': 'error', 'error': 'Invalid result type'}
        
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        return {'status': 'error', 'error': 'Operation interrupted by user'}
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        return {'status': 'error', 'error': str(e)}

if __name__ == "__main__":
    sys.exit(0 if main()['status'] == 'success' else 1)
        