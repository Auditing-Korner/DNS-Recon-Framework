#!/usr/bin/env python3

import argparse
import json
import logging
import socket
import sys
import os
import dns.resolver
import dns.exception
import requests
import re
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich.text import Text
from rich import box

# Handle imports for framework integration
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Initialize rich console
console = Console()

def print_banner():
    """Print a visually appealing banner"""
    title = Text()
    title.append("DNS Takeover Scanner", style="bold cyan")
    title.append("\nSubdomain Takeover Vulnerability Detection", style="blue")
    
    version = Text("\nVersion: 1.0.0", style="yellow")
    author = Text("\nAuthor: rfs85", style="green")
    
    features = Text("\n\nFeatures:", style="bold magenta")
    features.append("\n• Detects potential subdomain takeover vulnerabilities", style="magenta")
    features.append("\n• Supports multiple cloud providers and services", style="magenta")
    features.append("\n• Concurrent scanning with multi-threading", style="magenta")
    features.append("\n• Detailed vulnerability reporting", style="magenta")
    
    providers = Text("\n\nSupported Providers:", style="bold yellow")
    providers.append("\n• Amazon Web Services (S3, CloudFront)", style="yellow")
    providers.append("\n• Microsoft Azure", style="yellow")
    providers.append("\n• GitHub Pages", style="yellow")
    providers.append("\n• Heroku", style="yellow")
    providers.append("\n• And more...", style="yellow")
    
    banner = title + version + author + features + providers
    
    console.print(Panel(
        banner,
        title="[bold white]RFS DNS Framework[/bold white]",
        subtitle="[bold white]Security Testing Tool[/bold white]",
        border_style="blue",
        box=box.DOUBLE,
        padding=(1, 2),
        expand=False
    ))
    console.print()

# Known vulnerable services and their fingerprints
TAKEOVER_FINGERPRINTS = {
    "aws_s3": {
        "cname": [".s3.amazonaws.com", ".s3-website", ".amazonaws.com", ".aws.amazon.com"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "service": "Amazon S3",
        "status_code": [404],
        "vulnerable": True
    },
    "github": {
        "cname": [".github.io"],
        "fingerprint": ["There isn't a GitHub Pages site here", "Not Found"],
        "service": "GitHub Pages",
        "status_code": [404],
        "vulnerable": True
    },
    "azure": {
        "cname": [".azurewebsites.net", ".blob.core.windows.net", ".cloudapp.net", ".azure-api.net", ".azurewebsites.windows.net", ".azure.com"],
        "fingerprint": ["404 Web Site not found", "The specified CGI application encountered an error and the server terminated the process", "The resource you are looking for has been removed"],
        "service": "Microsoft Azure",
        "status_code": [404],
        "vulnerable": True
    },
    "cloudfront": {
        "cname": [".cloudfront.net"],
        "fingerprint": ["The request could not be satisfied", "ErrorMessage>The request could not be satisfied"],
        "service": "AWS CloudFront",
        "status_code": [404, 502, 503],
        "vulnerable": True
    },
    "heroku": {
        "cname": [".herokudns.com", ".herokuapp.com", ".herokussl.com"],
        "fingerprint": ["No such app", "Nothing to see here", "herokucdn.com/error-pages/no-such-app.html"],
        "service": "Heroku",
        "status_code": [404],
        "vulnerable": True
    },
    "fastly": {
        "cname": [".fastly.net"],
        "fingerprint": ["Fastly error: unknown domain", "This domain is not configured"],
        "service": "Fastly",
        "status_code": [404, 500, 503],
        "vulnerable": True
    },
    "zendesk": {
        "cname": [".zendesk.com"],
        "fingerprint": ["Help Center Closed", "this help center no longer exists", "page not found"],
        "service": "Zendesk",
        "status_code": [404],
        "vulnerable": True
    },
    "shopify": {
        "cname": [".myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable"],
        "service": "Shopify",
        "status_code": [404],
        "vulnerable": True
    },
    "tumblr": {
        "cname": [".tumblr.com"],
        "fingerprint": ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"],
        "service": "Tumblr",
        "status_code": [404],
        "vulnerable": True
    },
    "squarespace": {
        "cname": [".squarespace.com"],
        "fingerprint": ["You're in the right place but we can't find the page you're looking for", "Domain Not Found"],
        "service": "Squarespace",
        "status_code": [404],
        "vulnerable": True
    },
    "wix": {
        "cname": [".wixdns.net", ".wix.com"],
        "fingerprint": ["Error ConnectYourDomain occurred", "Domain not found"],
        "service": "Wix",
        "status_code": [404],
        "vulnerable": True
    }
}

@dataclass
class TakeoverResult:
    """Class to store takeover detection results"""
    subdomain: str
    cname: str
    ip_addresses: List[str]
    service: Optional[str]
    vulnerable: bool
    evidence: Optional[str]
    status_code: int
    risk_level: str

class DNSTakeoverScanner(BaseTool):
    """Scanner for potential subdomain takeover vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="dns-takeover",
            description="DNS subdomain takeover vulnerability scanner"
        )
        self.domain = None
        self.include_subdomains = True
        self.subdomains = []
        self.timeout = 5
        self.threads = 20
        self.verify_ssl = False
        self.custom_fingerprints = None
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        
        # Load fingerprints
        self.fingerprints = TAKEOVER_FINGERPRINTS
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        super().setup_argparse(parser)
        
        parser.add_argument("domain", help="Domain to scan for takeover vulnerabilities")
        parser.add_argument("--subdomains", "-s", 
                          help="File containing list of subdomains to check (one per line)")
        parser.add_argument("--no-subdomains", action="store_true",
                          help="Don't automatically enumerate subdomains")
        parser.add_argument("--timeout", "-t", type=int, default=5,
                          help="Connection timeout in seconds (default: 5)")
        parser.add_argument("--threads", type=int, default=20,
                          help="Number of concurrent threads (default: 20)")
        parser.add_argument("--verify-ssl", action="store_true",
                          help="Verify SSL certificates (default: False)")
        parser.add_argument("--custom-fingerprints",
                          help="Path to custom fingerprints JSON file")
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
        # Store arguments
        self.domain = args.domain.lower()
        self.include_subdomains = not args.no_subdomains
        self.timeout = args.timeout
        self.threads = args.threads
        self.verify_ssl = args.verify_ssl
        
        # Try to load custom fingerprints if specified
        if args.custom_fingerprints:
            self._load_custom_fingerprints(args.custom_fingerprints)
        
        # Create result object
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "scan_date": datetime.now().isoformat(),
                "domain": self.domain,
                "fingerprints_loaded": len(self.fingerprints)
            }
        )
        
        # Get subdomains to check
        if args.subdomains:
            self._load_subdomains_from_file(args.subdomains)
        elif self.include_subdomains:
            self._enumerate_subdomains()
        else:
            # Just check the main domain
            self.subdomains = [self.domain]
        
        result.metadata["subdomains_scanned"] = len(self.subdomains)
        
        # Check each subdomain for takeover vulnerabilities
        takeover_results = self._scan_subdomains()
        
        # Add findings based on results
        for takeover in takeover_results:
            if takeover.vulnerable:
                result.add_finding(
                    title=f"Potential subdomain takeover: {takeover.subdomain}",
                    description=f"The subdomain {takeover.subdomain} is vulnerable to takeover via {takeover.service}",
                    risk_level=takeover.risk_level,
                    evidence=f"CNAME: {takeover.cname}\nService: {takeover.service}\nEvidence: {takeover.evidence}"
                )
        
        # Add metadata with full results
        result.metadata["results"] = [self._result_to_dict(r) for r in takeover_results]
        
        return result
    
    def _load_custom_fingerprints(self, filepath: str) -> None:
        """Load custom takeover fingerprints from JSON file"""
        try:
            with open(filepath, 'r') as f:
                custom_fingerprints = json.load(f)
                
                # Validate and add custom fingerprints
                for name, data in custom_fingerprints.items():
                    if all(key in data for key in ["cname", "fingerprint", "service", "status_code", "vulnerable"]):
                        self.fingerprints[name] = data
                        self.logger.info(f"Loaded custom fingerprint: {name}")
                    else:
                        self.logger.warning(f"Invalid fingerprint format for {name}, skipping")
                
        except Exception as e:
            self.logger.error(f"Error loading custom fingerprints: {str(e)}")
    
    def _load_subdomains_from_file(self, filepath: str) -> None:
        """Load subdomains from a file"""
        try:
            with open(filepath, 'r') as f:
                self.subdomains = [line.strip().lower() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(self.subdomains)} subdomains from {filepath}")
        except Exception as e:
            self.logger.error(f"Error loading subdomains from file: {str(e)}")
            self.subdomains = [self.domain]  # Fallback to main domain
    
    def _enumerate_subdomains(self) -> None:
        """Enumerate subdomains using DNS queries"""
        self.logger.info(f"Enumerating subdomains for {self.domain}")
        
        discovered = set()
        discovered.add(self.domain)
        
        # First try to get subdomains from common DNS records
        try:
            # Check NS records
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for record in ns_records:
                ns = str(record.target).rstrip('.')
                if self.domain in ns and ns not in discovered:
                    discovered.add(ns)
            
            # Check MX records
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            for record in mx_records:
                mx = str(record.exchange).rstrip('.')
                if self.domain in mx and mx not in discovered:
                    discovered.add(mx)
                    
            # Check TXT records for potential subdomains
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            for record in txt_records:
                txt = str(record).rstrip('.')
                # Look for subdomains in TXT records (common in SPF records)
                for part in txt.split():
                    if self.domain in part and part not in discovered:
                        potential_subdomain = part.replace('"', '').replace("'", "")
                        if potential_subdomain.endswith(self.domain) and "." in potential_subdomain:
                            discovered.add(potential_subdomain)
                            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
            
        # Try common subdomains
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
            'smtp', 'secure', 'vpn', 'api', 'dev', 'stage', 'test', 'portal', 
            'admin', 'cdn', 'static', 'app', 'support', 'docs', 'media', 'shop', 
            'ftp', 'cloud', 'auth', 'beta'
        ]
        
        for sub in common_subdomains:
            fqdn = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(fqdn)  # Check if resolves
                discovered.add(fqdn)
                self.logger.debug(f"Found subdomain: {fqdn}")
            except:
                pass
        
        self.subdomains = list(discovered)
        self.logger.info(f"Discovered {len(self.subdomains)} subdomains")
    
    def _scan_subdomains(self) -> List[TakeoverResult]:
        """Scan subdomains for takeover vulnerabilities"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(self._check_subdomain, subdomain): subdomain for subdomain in self.subdomains}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error checking {subdomain}: {str(e)}")
        
        return results
    
    def _check_subdomain(self, subdomain: str) -> Optional[TakeoverResult]:
        """Check a single subdomain for takeover vulnerability"""
        self.logger.debug(f"Checking {subdomain}")
        
        # Initialize result with defaults
        result = TakeoverResult(
            subdomain=subdomain,
            cname="",
            ip_addresses=[],
            service=None,
            vulnerable=False,
            evidence=None,
            status_code=0,
            risk_level="Low"
        )
        
        try:
            # Get CNAME records
            try:
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                cname = str(answers[0].target).rstrip('.')
                result.cname = cname
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                # No CNAME, try to get A record
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    result.ip_addresses = [str(record) for record in answers]
                except:
                    # Neither CNAME nor A record found, could be dangling
                    pass
            
            # If we have a CNAME but couldn't resolve it to an IP, this is a good candidate
            if result.cname and not result.ip_addresses:
                # Try to resolve CNAME to IP
                try:
                    answers = dns.resolver.resolve(result.cname, 'A')
                    result.ip_addresses = [str(record) for record in answers]
                except:
                    # CNAME exists but doesn't resolve to an IP, potential takeover
                    self.logger.info(f"Found dangling CNAME: {subdomain} -> {result.cname}")
                    
                    # Try to match CNAME with known vulnerable services
                    for service_name, service_data in self.fingerprints.items():
                        if isinstance(service_data, dict) and "cname" in service_data:
                            for cname_pattern in service_data["cname"]:
                                if cname_pattern in result.cname:
                                    # Found a match, check if it's vulnerable
                                    result.service = service_data.get("service", service_name)
                                    
                                    # Now try to connect to the subdomain to check for takeover evidence
                                    http_result = self._check_http_evidence(subdomain, service_data)
                                    if http_result:
                                        result.status_code = http_result["status_code"]
                                        result.evidence = http_result["evidence"]
                                        result.vulnerable = http_result["vulnerable"]
                                        
                                        # Set risk level based on vulnerability
                                        if result.vulnerable:
                                            result.risk_level = "High"  # Confirmed takeover vulnerability
                                        
                                        return result
            
            # Check for HTTP evidence even for resolving subdomains
            # as sometimes there might be takeover evidence in the response
            if result.ip_addresses:
                for service_name, service_data in self.fingerprints.items():
                    if isinstance(service_data, dict) and "cname" in service_data and result.cname:
                        # Check if CNAME matches the service
                        cname_match = any(pattern in result.cname for pattern in service_data["cname"])
                        if cname_match:
                            result.service = service_data.get("service", service_name)
                            
                            # Check HTTP evidence
                            http_result = self._check_http_evidence(subdomain, service_data)
                            if http_result and http_result["vulnerable"]:
                                result.status_code = http_result["status_code"]
                                result.evidence = http_result["evidence"]
                                result.vulnerable = True
                                result.risk_level = "High"
                                return result
                    
            # Return result even if not vulnerable (for reporting)
            if result.cname or result.ip_addresses:
                return result
            
            return None
                
        except Exception as e:
            self.logger.error(f"Error checking {subdomain}: {str(e)}")
            return None
    
    def _check_http_evidence(self, subdomain: str, service_data: Dict) -> Optional[Dict]:
        """Check for HTTP evidence of takeover vulnerability"""
        try:
            # Try HTTPS first, then fallback to HTTP
            for protocol in ["https", "http"]:
                url = f"{protocol}://{subdomain}"
                try:
                    headers = {
                        "User-Agent": self.user_agent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Connection": "close"
                    }
                    
                    response = requests.get(
                        url, 
                        headers=headers, 
                        timeout=self.timeout, 
                        verify=self.verify_ssl,
                        allow_redirects=True
                    )
                    
                    # Check status code
                    if response.status_code in service_data["status_code"]:
                        # Check for fingerprint matches in response content
                        content = response.text.lower()
                        for fingerprint in service_data["fingerprint"]:
                            if fingerprint.lower() in content:
                                return {
                                    "status_code": response.status_code,
                                    "evidence": fingerprint,
                                    "vulnerable": service_data["vulnerable"]
                                }
                    
                    # No fingerprint match
                    return {
                        "status_code": response.status_code,
                        "evidence": None,
                        "vulnerable": False
                    }
                    
                except requests.RequestException:
                    continue
            
            # Both HTTPS and HTTP failed
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking HTTP evidence for {subdomain}: {str(e)}")
            return None
    
    def _result_to_dict(self, result: TakeoverResult) -> Dict:
        """Convert TakeoverResult to dictionary for output"""
        return {
            "subdomain": result.subdomain,
            "cname": result.cname,
            "ip_addresses": result.ip_addresses,
            "service": result.service,
            "vulnerable": result.vulnerable,
            "evidence": result.evidence,
            "status_code": result.status_code,
            "risk_level": result.risk_level
        }

def main():
    tool = DNSTakeoverScanner()
    return tool.main()

if __name__ == "__main__":
    main() 