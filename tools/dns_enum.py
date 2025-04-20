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

    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if required dependencies are available"""
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import requests
            return True, None
        except ImportError as e:
            return False, f"Missing dependency: {str(e)}"

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
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
        self.results["metadata"]["domain"] = self.domain
        self.results["metadata"]["scan_time"] = datetime.now().isoformat()
        self.results["metadata"]["arguments"] = {
            "timeout": self.timeout,
            "threads": self.threads,
            "resolve_ips": self.resolve_ips,
            "check_wildcard": self.check_wildcard,
            "detect_providers": self.detect_providers,
            "max_depth": self.max_depth
        }
        
        # If listing wordlists was requested
        if hasattr(args, 'list') and args.list:
            self._list_wordlists()
            # Create an empty result since we're just listing wordlists
            result = ToolResult(
                success=True,
                tool_name=self.name,
                findings=[],
                metadata={"action": "list_wordlists"}
            )
            return result
        
        # Run enumeration
        self.run_enumeration()
        
        # Create tool result
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata=self.results
        )
        
        # Add findings based on results
        self._add_findings_to_result(result)
        
        # Finalize the result before returning
        result.finalize()
        
        return result

    def run_enumeration(self):
        """Run the full DNS enumeration process"""
        if self.framework_mode:
            self.logger.info(f"Starting DNS enumeration for {self.domain}")
        else:
            print(f"[*] Starting DNS enumeration for {self.domain}")
        
        start_time = time.time()
        
        try:
            # Detect nameservers
            self.detect_nameservers()
            
            # Enumerate DNS records
            self.enumerate_records()
            
            # Attempt zone transfer
            self.attempt_zone_transfer()
            
            # Check for wildcard DNS if enabled
            if self.check_wildcard:
                self.detect_wildcard_dns()
            
            # Perform subdomain enumeration
            self.enumerate_subdomains()
            
            # Additional analysis
            if len(self.results["subdomains"]) > 0:
                self.analyze_infrastructure()
                if self.resolve_ips:
                    self.reverse_lookup_ips()
                    
            # Detect cloud hosting providers if enabled
            if self.detect_providers:
                self.detect_cloud_providers()
            
            # Calculate execution time
            end_time = time.time()
            execution_time = end_time - start_time
            self.results["metadata"]["execution_time_seconds"] = execution_time
            
            if self.framework_mode:
                self.logger.info(f"DNS enumeration completed in {execution_time:.2f} seconds")
            else:
                print(f"[+] DNS enumeration completed in {execution_time:.2f} seconds")
                
        except Exception as e:
            error_msg = f"Error during DNS enumeration: {str(e)}"
            if self.framework_mode:
                self.logger.error(error_msg)
            else:
                print(f"[!] {error_msg}")
            # Add error to results
            if "errors" not in self.results["metadata"]:
                self.results["metadata"]["errors"] = []
            self.results["metadata"]["errors"].append(str(e))
            
            # Include traceback in verbose mode
            if self.verbose:
                if "debug_info" not in self.results["metadata"]:
                    self.results["metadata"]["debug_info"] = []
                self.results["metadata"]["debug_info"].append(traceback.format_exc())
                
                if not self.framework_mode:
                    print(traceback.format_exc())

    def detect_nameservers(self):
        """Detect authoritative nameservers for the domain"""
        if self.framework_mode:
            self.logger.info("Detecting nameservers...")
        else:
            print("[*] Detecting nameservers...")
        
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for record in ns_records:
                ns_hostname = str(record.target).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_hostname)
                    self.results["nameservers"].append({
                        "hostname": ns_hostname,
                        "ip": ns_ip
                    })
                    
                    message = f"Found nameserver: {ns_hostname} ({ns_ip})"
                    if self.framework_mode:
                        self.logger.info(message)
                    else:
                        print(f"[+] {message}")
                        
                except socket.gaierror:
                    message = f"Could not resolve IP for nameserver: {ns_hostname}"
                    if self.framework_mode:
                        self.logger.warning(message)
                    else:
                        print(f"[!] {message}")
        except Exception as e:
            message = f"Error detecting nameservers: {e}"
            if self.framework_mode:
                self.logger.error(message)
            else:
                print(f"[!] {message}")

    def enumerate_records(self):
        """Enumerate common DNS record types"""
        if self.framework_mode:
            self.logger.info("Enumerating DNS records...")
        else:
            print("[*] Enumerating DNS records...")
            
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results["records"][record_type] = [str(rdata) for rdata in answers]
                
                message = f"Found {len(answers)} {record_type} record(s)"
                if self.framework_mode:
                    self.logger.info(message)
                else:
                    print(f"[+] {message}")
            except:
                continue

    def attempt_zone_transfer(self):
        """Attempt zone transfer with each nameserver"""
        if self.framework_mode:
            self.logger.info("Attempting zone transfer...")
        else:
            print("[*] Attempting zone transfer...")
            
        self.results["zone_transfer"]["attempted"] = True
        
        for ns in self.results["nameservers"]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns["ip"], self.domain))
                self.results["zone_transfer"]["successful"] = True
                self.results["zone_transfer"]["results"].extend([
                    str(name) + " " + str(node.rdatasets)
                    for name, node in zone.nodes.items()
                ])
                
                message = f"Zone transfer successful from {ns['hostname']}"
                if self.framework_mode:
                    self.logger.warning(message)
                else:
                    print(f"[!] {message}")
                break
            except:
                continue

    def detect_wildcard_dns(self):
        """Detect wildcard DNS records"""
        if self.framework_mode:
            self.logger.info("Checking for wildcard DNS...")
        else:
            print("[*] Checking for wildcard DNS...")
            
        test_subdomains = [
            f"wildcard-test-{random.randint(100000,999999)}" for _ in range(3)
        ]
        
        wildcard_ips = set()
        for subdomain in test_subdomains:
            try:
                answers = dns.resolver.resolve(f"{subdomain}.{self.domain}", 'A')
                wildcard_ips.update([str(rdata) for rdata in answers])
            except:
                continue
        
        if wildcard_ips:
            self.results["wildcard_detection"]["detected"] = True
            self.results["wildcard_detection"]["ips"] = list(wildcard_ips)
            
            message = f"Wildcard DNS detected: {', '.join(wildcard_ips)}"
            if self.framework_mode:
                self.logger.warning(message)
            else:
                print(f"[!] {message}")

    def enumerate_subdomains(self):
        """Enumerate subdomains using various techniques"""
        if self.framework_mode:
            self.logger.info("Enumerating subdomains...")
        else:
            print("[*] Enumerating subdomains...")
        
        # Start with basic enumeration techniques
        self._enumerate_common_subdomains()
        
        # If we have a wordlist, use it for brute force
        if self.wordlist:
            self._bruteforce_subdomains()

    def _enumerate_common_subdomains(self):
        """Enumerate common subdomains"""
        common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server',
                           'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'admin',
                           'ftp', 'test', 'portal', 'dev', 'staging', 'apps', 'shop']
        
        found_count = 0
        for subdomain in common_subdomains:
            fqdn = f"{subdomain}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                self.results["subdomains"].append({
                    "name": fqdn,
                    "type": "A",
                    "ips": [str(rdata) for rdata in answers]
                })
                
                message = f"Found subdomain: {fqdn}"
                if self.framework_mode:
                    self.logger.info(message)
                else:
                    print(f"[+] {message}")
                    
                found_count += 1
            except:
                continue
                
        if found_count == 0:
            message = "No common subdomains found"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[*] {message}")
        else:
            message = f"Found {found_count} common subdomains"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[+] {message}")

    def _list_wordlists(self):
        """List available wordlists for subdomain enumeration"""
        if self.framework_mode:
            self.logger.info("Available wordlists:")
            for category, wordlists in WORDLIST_CATEGORIES.items():
                self.logger.info(f"  {category.upper()}:")
                for wl in wordlists:
                    url = WORDLIST_PATHS.get(wl, "N/A")
                    self.logger.info(f"    - {wl}: {url}")
        else:
            print(f"\n[*] Available Wordlists:")
            for category, wordlists in WORDLIST_CATEGORIES.items():
                print(f"\n  {category.upper()}:")
                for wl in wordlists:
                    url = WORDLIST_PATHS.get(wl, "N/A")
                    print(f"    - {wl}: {url}")
            print("\nUsage: dns_enum.py example.com -w tiny")

    def _get_wordlist(self, wordlist_name):
        """Get a wordlist by name or path"""
        if wordlist_name in WORDLIST_PATHS:
            # This is a predefined wordlist
            url = WORDLIST_PATHS[wordlist_name]
            message = f"Downloading wordlist '{wordlist_name}' from {url}"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[*] {message}")
                
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    return response.text.splitlines()
                else:
                    error_msg = f"Error downloading wordlist: {response.status_code}"
                    if self.framework_mode:
                        self.logger.error(error_msg)
                    else:
                        print(f"[!] {error_msg}")
                    return []
            except Exception as e:
                error_msg = f"Error downloading wordlist: {e}"
                if self.framework_mode:
                    self.logger.error(error_msg)
                else:
                    print(f"[!] {error_msg}")
                return []
        elif os.path.exists(wordlist_name):
            # This is a file path
            message = f"Reading wordlist from file: {wordlist_name}"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[*] {message}")
                
            try:
                with open(wordlist_name, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                error_msg = f"Error reading wordlist file: {e}"
                if self.framework_mode:
                    self.logger.error(error_msg)
                else:
                    print(f"[!] {error_msg}")
                return []
        else:
            error_msg = f"Wordlist not found: {wordlist_name}"
            if self.framework_mode:
                self.logger.error(error_msg)
            else:
                print(f"[!] {error_msg}")
            return []

    def _bruteforce_subdomains(self):
        """Bruteforce subdomains using wordlist"""
        if not self.wordlist:
            message = "No wordlist specified for bruteforce"
            if self.framework_mode:
                self.logger.warning(message)
            else:
                print(f"[!] {message}")
            return
        
        subdomains = self._get_wordlist(self.wordlist)
        if not subdomains:
            message = "Wordlist is empty or could not be loaded"
            if self.framework_mode:
                self.logger.warning(message)
            else:
                print(f"[!] {message}")
            return
        
        message = f"Starting bruteforce with {len(subdomains)} subdomains..."
        if self.framework_mode:
            self.logger.info(message)
        else:
            print(f"[*] {message}")
            
        # Set up progress tracking
        found_count = 0
        total_count = len(subdomains)
        start_time = time.time()
        
        # Use rich progress bar if not in framework mode
        if not self.framework_mode and total_count > 100:
            with Progress() as progress:
                task = progress.add_task("[cyan]Bruteforcing subdomains...", total=total_count)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_subdomain = {
                        executor.submit(self._check_subdomain, sub): sub 
                        for sub in subdomains
                    }
                    
                    for i, future in enumerate(concurrent.futures.as_completed(future_to_subdomain)):
                        subdomain = future_to_subdomain[future]
                        try:
                            result = future.result()
                            if result:
                                self.results["subdomains"].append(result)
                                found_count += 1
                                print(f"[+] Found subdomain: {result['name']}")
                        except Exception as e:
                            if self.verbose:
                                print(f"[!] Error checking {subdomain}: {e}")
                        
                        # Update progress
                        progress.update(task, completed=i+1)
                        
                        # Respect rate limiting if enabled
                        if self.rate_limit > 0:
                            time.sleep(1.0 / self.rate_limit)
        else:
            # Simpler execution for framework mode or smaller wordlists
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {
                    executor.submit(self._check_subdomain, sub): sub 
                    for sub in subdomains
                }
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        result = future.result()
                        if result:
                            self.results["subdomains"].append(result)
                            found_count += 1
                            
                            message = f"Found subdomain: {result['name']}"
                            if self.framework_mode:
                                self.logger.info(message)
                            else:
                                print(f"[+] {message}")
                    except Exception as e:
                        if self.verbose:
                            error_msg = f"Error checking {subdomain}: {e}"
                            if self.framework_mode:
                                self.logger.debug(error_msg)
                            else:
                                print(f"[!] {error_msg}")
                    
                    # Respect rate limiting if enabled
                    if self.rate_limit > 0:
                        time.sleep(1.0 / self.rate_limit)
        
        # Report completion statistics
        end_time = time.time()
        duration = end_time - start_time
        completion_msg = f"Bruteforce completed: found {found_count} subdomains in {duration:.2f} seconds"
        if self.framework_mode:
            self.logger.info(completion_msg)
        else:
            print(f"[+] {completion_msg}")

    def _check_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Check if a subdomain exists"""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            answers = dns.resolver.resolve(fqdn, 'A')
            return {
                "name": fqdn,
                "type": "A",
                "ips": [str(rdata) for rdata in answers],
                "discovery_method": "bruteforce"
            }
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except Exception as e:
            if self.verbose:
                error_msg = f"Error resolving {fqdn}: {str(e)}"
                if self.framework_mode:
                    self.logger.debug(error_msg)
            return None

    def analyze_infrastructure(self):
        """Analyze DNS infrastructure patterns"""
        if self.framework_mode:
            self.logger.info("Analyzing infrastructure...")
        else:
            print("[*] Analyzing infrastructure...")
        
        # Analyze IP ranges
        ip_ranges = defaultdict(list)
        for subdomain in self.results["subdomains"]:
            for ip in subdomain.get("ips", []):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    network = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
                    ip_ranges[str(network)].append(subdomain["name"])
                except:
                    continue
        
        # Add analysis to results
        self.results["infrastructure"]["ip_ranges"] = [
            {"network": network, "subdomains": subdomains}
            for network, subdomains in ip_ranges.items()
        ]

    def reverse_lookup_ips(self):
        """Perform reverse DNS lookups"""
        if self.framework_mode:
            self.logger.info("Performing reverse DNS lookups...")
        else:
            print("[*] Performing reverse DNS lookups...")
        
        unique_ips = set()
        for subdomain in self.results["subdomains"]:
            unique_ips.update(subdomain.get("ips", []))
        
        for ip in unique_ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.results["infrastructure"]["ptr_records"].append({
                    "ip": ip,
                    "hostname": hostname
                })
                
                message = f"Reverse DNS: {ip} -> {hostname}"
                if self.framework_mode:
                    self.logger.info(message)
                else:
                    print(f"[+] {message}")
            except:
                continue

    def detect_cloud_providers(self):
        """Detect cloud providers from DNS records and subdomains"""
        if self.framework_mode:
            self.logger.info("Detecting cloud providers...")
        else:
            print("[*] Detecting cloud providers...")
        
        # Initialize providers counters
        provider_counts = defaultdict(int)
        provider_evidence = defaultdict(list)
        
        # Check for cloud provider evidence in CNAME records
        for subdomain in self.results["subdomains"]:
            subdomain_name = subdomain["name"]
            
            # Check for CNAME records
            try:
                cname_records = dns.resolver.resolve(subdomain_name, 'CNAME')
                for record in cname_records:
                    cname_target = str(record.target).rstrip('.')
                    
                    # Check against cloud provider patterns
                    for provider_name, provider_data in CLOUD_PROVIDERS.items():
                        # Check domain patterns
                        for domain_pattern in provider_data.get("domains", []):
                            if domain_pattern in cname_target:
                                provider_counts[provider_name] += 1
                                provider_evidence[provider_name].append({
                                    "type": "CNAME",
                                    "subdomain": subdomain_name,
                                    "target": cname_target,
                                    "pattern_matched": domain_pattern
                                })
                                break
                        
                        # Check regex patterns
                        for regex_pattern in provider_data.get("cnames", []):
                            if re.search(regex_pattern, cname_target):
                                provider_counts[provider_name] += 1
                                provider_evidence[provider_name].append({
                                    "type": "CNAME_REGEX",
                                    "subdomain": subdomain_name,
                                    "target": cname_target,
                                    "pattern_matched": regex_pattern
                                })
                                break
            except:
                pass
            
            # Check IP addresses against cloud IP ranges
            for ip in subdomain.get("ips", []):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    
                    for provider_name, provider_data in CLOUD_PROVIDERS.items():
                        for cidr in provider_data.get("ip_prefixes", []):
                            try:
                                if ip_obj in ipaddress.ip_network(cidr):
                                    provider_counts[provider_name] += 1
                                    provider_evidence[provider_name].append({
                                        "type": "IP_RANGE",
                                        "subdomain": subdomain_name,
                                        "ip": ip,
                                        "cidr": cidr
                                    })
                                    break
                            except:
                                continue
                except:
                    continue
        
        # Analyze TXT records for additional evidence
        try:
            txt_records = self.results["records"].get("TXT", [])
            for txt in txt_records:
                txt_lower = txt.lower()
                
                # Check for specific cloud provider verification records
                if "google-site-verification" in txt_lower:
                    provider_counts["GCP"] += 1
                    provider_evidence["GCP"].append({
                        "type": "TXT",
                        "record": txt,
                        "evidence": "google-site-verification"
                    })
                
                elif "ms=" in txt_lower or "microsoft-site-verification" in txt_lower:
                    provider_counts["Azure"] += 1
                    provider_evidence["Azure"].append({
                        "type": "TXT",
                        "record": txt,
                        "evidence": "microsoft verification"
                    })
                
                elif "amazon-site-verification" in txt_lower:
                    provider_counts["AWS"] += 1
                    provider_evidence["AWS"].append({
                        "type": "TXT",
                        "record": txt, 
                        "evidence": "amazon verification"
                    })
                
                elif "cloudflare-verify" in txt_lower:
                    provider_counts["Cloudflare"] += 1
                    provider_evidence["Cloudflare"].append({
                        "type": "TXT",
                        "record": txt,
                        "evidence": "cloudflare verification"
                    })
        except:
            pass
        
        # Store results
        self.results["hosting_providers"]["summary"] = dict(provider_counts)
        self.results["hosting_providers"]["details"] = dict(provider_evidence)
        
        # Log findings
        if provider_counts:
            message = f"Detected {len(provider_counts)} cloud providers: {', '.join(provider_counts.keys())}"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[+] {message}")
            
            for provider, count in provider_counts.items():
                details = f"Provider: {provider}, Evidence count: {count}"
                if self.framework_mode:
                    self.logger.info(details)
                else:
                    print(f"    - {details}")
        else:
            message = "No cloud providers detected"
            if self.framework_mode:
                self.logger.info(message)
            else:
                print(f"[*] {message}")
                
        return provider_counts

    def _add_findings_to_result(self, result: ToolResult):
        """Add findings to the tool result"""
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

def main():
    tool = DNSEnumerator()
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
        