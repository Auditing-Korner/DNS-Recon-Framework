#!/usr/bin/env python3
"""
Subdomain Takeover Tester
Advanced tool for testing and verifying subdomain takeover vulnerabilities
"""

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
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.logging import RichHandler

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
    title.append("Subdomain Takeover Tester", style="bold cyan")
    title.append("\nAdvanced Subdomain Vulnerability Analysis", style="blue")
    
    version = Text("\nVersion: 1.0.0", style="yellow")
    author = Text("\nAuthor: rfs85", style="green")
    
    features = Text("\n\nFeatures:", style="bold magenta")
    features.append("\n• Active & Passive Subdomain Discovery", style="magenta")
    features.append("\n• Automated Vulnerability Verification", style="magenta")
    features.append("\n• Cloud Service Provider Detection", style="magenta")
    features.append("\n• DNS Configuration Analysis", style="magenta")
    features.append("\n• Proof-of-Concept Generation", style="magenta")
    
    tests = Text("\n\nTests Performed:", style="bold yellow")
    tests.append("\n• CNAME Record Analysis", style="yellow")
    tests.append("\n• DNS Resolution Verification", style="yellow")
    tests.append("\n• Service Fingerprinting", style="yellow")
    tests.append("\n• SSL/TLS Certificate Checks", style="yellow")
    tests.append("\n• HTTP Response Analysis", style="yellow")
    
    banner = title + version + author + features + tests
    
    console.print(Panel(
        banner,
        title="[bold white]RFS DNS Framework[/bold white]",
        subtitle="[bold white]Security Testing Tool[/bold white]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2),
        expand=False
    ))
    console.print()

@dataclass
class SubdomainInfo:
    """Class to store subdomain information"""
    name: str
    cname: Optional[str] = None
    a_records: List[str] = None
    aaaa_records: List[str] = None
    ns_records: List[str] = None
    mx_records: List[str] = None
    txt_records: List[str] = None
    provider: Optional[str] = None
    is_vulnerable: bool = False
    vulnerability_type: Optional[str] = None
    evidence: Optional[str] = None
    risk_level: str = "Low"
    http_status: Optional[int] = None
    ssl_info: Optional[Dict] = None
    
    def __post_init__(self):
        self.a_records = self.a_records or []
        self.aaaa_records = self.aaaa_records or []
        self.ns_records = self.ns_records or []
        self.mx_records = self.mx_records or []
        self.txt_records = self.txt_records or []
        self.ssl_info = self.ssl_info or {}

class SubdomainTakeoverTester(BaseTool):
    """Advanced Subdomain Takeover Testing Tool"""
    
    def __init__(self):
        super().__init__(
            name="subdomain-takeover-tester",
            description="Advanced Subdomain Takeover Testing Tool"
        )
        self.domain = None
        self.subdomains = set()
        self.results = []
        self.threads = 20
        self.timeout = 10
        self.verify_ssl = False
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            handlers=[RichHandler(rich_tracebacks=True)]
        )
        self.logger = logging.getLogger("subdomain_tester")
        
        # Load provider signatures
        self.providers = self._load_provider_signatures()
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        super().setup_argparse(parser)
        
        parser.add_argument("domain", help="Target domain to test")
        parser.add_argument("-s", "--subdomains", help="File containing list of subdomains")
        parser.add_argument("-t", "--threads", type=int, default=20,
                          help="Number of concurrent threads (default: 20)")
        parser.add_argument("--timeout", type=int, default=10,
                          help="Timeout for requests in seconds (default: 10)")
        parser.add_argument("--verify-ssl", action="store_true",
                          help="Verify SSL certificates")
        parser.add_argument("--passive", action="store_true",
                          help="Only use passive subdomain enumeration")
        parser.add_argument("--active", action="store_true",
                          help="Only use active subdomain enumeration")
        parser.add_argument("--dns-servers", nargs="+",
                          help="Custom DNS servers to use")
        parser.add_argument("--output", "-o", help="Output file for results")
        parser.add_argument("--format", choices=["json", "html", "text"],
                          default="text", help="Output format")
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool"""
        print_banner()
        
        # Initialize result
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": args.domain,
                "scan_date": datetime.now().isoformat()
            }
        )
        
        try:
            # Store configuration
            self.domain = args.domain.lower()
            self.threads = args.threads
            self.timeout = args.timeout
            self.verify_ssl = args.verify_ssl
            
            # Configure custom DNS servers if specified
            if args.dns_servers:
                self._configure_dns_servers(args.dns_servers)
            
            # Discover subdomains
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Discovering subdomains...", total=None)
                
                if args.subdomains:
                    self._load_subdomains_from_file(args.subdomains)
                elif args.passive:
                    self._passive_subdomain_enumeration()
                elif args.active:
                    self._active_subdomain_enumeration()
                else:
                    # Use both methods by default
                    self._passive_subdomain_enumeration()
                    self._active_subdomain_enumeration()
                
                progress.update(task, completed=True)
            
            # Test discovered subdomains
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Testing {len(self.subdomains)} subdomains...", total=len(self.subdomains))
                
                for subdomain_info in self._test_subdomains(progress, task):
                    if subdomain_info.is_vulnerable:
                        result.add_finding(
                            title=f"Subdomain Takeover: {subdomain_info.name}",
                            description=f"Vulnerable to takeover via {subdomain_info.provider}",
                            risk_level=subdomain_info.risk_level,
                            evidence=self._format_evidence(subdomain_info)
                        )
            
            # Generate output
            if args.output:
                self._save_results(args.output, args.format)
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during testing: {str(e)}")
            return result
    
    def _load_provider_signatures(self) -> Dict:
        """Load provider signatures from providers.json"""
        try:
            providers_file = Path(__file__).parent / "data" / "providers.json"
            with open(providers_file) as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading provider signatures: {e}")
            return {}
    
    def _configure_dns_servers(self, servers: List[str]) -> None:
        """Configure custom DNS servers"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = servers
        dns.resolver.default_resolver = resolver
    
    def _load_subdomains_from_file(self, filepath: str) -> None:
        """Load subdomains from file"""
        try:
            with open(filepath) as f:
                self.subdomains.update(line.strip().lower() for line in f if line.strip())
        except Exception as e:
            self.logger.error(f"Error loading subdomains from file: {e}")
    
    def _passive_subdomain_enumeration(self) -> None:
        """Perform passive subdomain enumeration"""
        # Implement passive enumeration methods (certificates, search engines, etc.)
        pass
    
    def _active_subdomain_enumeration(self) -> None:
        """Perform active subdomain enumeration"""
        # Implement active enumeration methods (bruteforce, zone transfers, etc.)
        pass
    
    def _test_subdomains(self, progress: Progress, task: int) -> List[SubdomainInfo]:
        """Test subdomains for takeover vulnerabilities"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self._test_single_subdomain, subdomain): subdomain 
                for subdomain in self.subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error testing {subdomain}: {e}")
                finally:
                    progress.update(task, advance=1)
        
        return results
    
    def _test_single_subdomain(self, subdomain: str) -> Optional[SubdomainInfo]:
        """Test a single subdomain for takeover vulnerability"""
        info = SubdomainInfo(name=subdomain)
        
        try:
            # Get DNS records
            self._get_dns_records(info)
            
            # If we have a CNAME, check for takeover
            if info.cname:
                self._check_cname_takeover(info)
            
            # Check HTTP/HTTPS
            self._check_http_evidence(info)
            
            # Check SSL certificate
            if not info.ssl_info:
                self._check_ssl_certificate(info)
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error testing {subdomain}: {e}")
            return None
    
    def _get_dns_records(self, info: SubdomainInfo) -> None:
        """Get all DNS records for a subdomain"""
        try:
            # Get CNAME
            try:
                answers = dns.resolver.resolve(info.name, 'CNAME')
                info.cname = str(answers[0].target).rstrip('.')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get A records
            try:
                answers = dns.resolver.resolve(info.name, 'A')
                info.a_records = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get AAAA records
            try:
                answers = dns.resolver.resolve(info.name, 'AAAA')
                info.aaaa_records = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get NS records
            try:
                answers = dns.resolver.resolve(info.name, 'NS')
                info.ns_records = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get MX records
            try:
                answers = dns.resolver.resolve(info.name, 'MX')
                info.mx_records = [str(rdata.exchange) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get TXT records
            try:
                answers = dns.resolver.resolve(info.name, 'TXT')
                info.txt_records = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
        except Exception as e:
            self.logger.error(f"Error getting DNS records for {info.name}: {e}")
    
    def _check_cname_takeover(self, info: SubdomainInfo) -> None:
        """Check if CNAME record indicates potential takeover"""
        for provider, signatures in self.providers.items():
            if any(pattern in info.cname for pattern in signatures.get('cname_patterns', [])):
                info.provider = provider
                
                # Try to resolve the CNAME
                try:
                    dns.resolver.resolve(info.cname, 'A')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    info.is_vulnerable = True
                    info.vulnerability_type = "Dangling CNAME"
                    info.risk_level = "High"
                    info.evidence = f"CNAME {info.cname} does not resolve"
    
    def _check_http_evidence(self, info: SubdomainInfo) -> None:
        """Check for takeover evidence in HTTP responses"""
        for protocol in ['https', 'http']:
            try:
                response = requests.get(
                    f"{protocol}://{info.name}",
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                
                info.http_status = response.status_code
                
                # Check response against provider fingerprints
                if info.provider:
                    provider_data = self.providers.get(info.provider, {})
                    fingerprints = provider_data.get('fingerprints', [])
                    
                    for fingerprint in fingerprints:
                        if fingerprint.lower() in response.text.lower():
                            info.is_vulnerable = True
                            info.vulnerability_type = "Service Not Claimed"
                            info.risk_level = "High"
                            info.evidence = f"Found fingerprint: {fingerprint}"
                            return
                
                break  # Stop if we get a successful response
                
            except requests.RequestException:
                continue
    
    def _check_ssl_certificate(self, info: SubdomainInfo) -> None:
        """Check SSL certificate for additional information"""
        try:
            response = requests.get(
                f"https://{info.name}",
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.ok:
                cert = response.raw.connection.sock.getpeercert()
                info.ssl_info = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serialNumber': cert['serialNumber'],
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter']
                }
        except:
            pass
    
    def _format_evidence(self, info: SubdomainInfo) -> str:
        """Format evidence for reporting"""
        evidence = []
        
        if info.cname:
            evidence.append(f"CNAME: {info.cname}")
        
        if info.a_records:
            evidence.append(f"A Records: {', '.join(info.a_records)}")
        
        if info.vulnerability_type:
            evidence.append(f"Vulnerability Type: {info.vulnerability_type}")
        
        if info.evidence:
            evidence.append(f"Evidence: {info.evidence}")
        
        if info.http_status:
            evidence.append(f"HTTP Status: {info.http_status}")
        
        if info.ssl_info:
            evidence.append("SSL Certificate Info:")
            for key, value in info.ssl_info.items():
                evidence.append(f"  {key}: {value}")
        
        return "\n".join(evidence)
    
    def _save_results(self, filepath: str, format: str) -> None:
        """Save results to file"""
        try:
            if format == "json":
                with open(filepath, 'w') as f:
                    json.dump(self.results, f, indent=2)
            elif format == "html":
                self._generate_html_report(filepath)
            else:
                with open(filepath, 'w') as f:
                    for result in self.results:
                        f.write(f"{result}\n")
            
            self.logger.info(f"Results saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
    
    def _generate_html_report(self, filepath: str) -> None:
        """Generate HTML report"""
        # Implement HTML report generation
        pass

def main():
    tool = SubdomainTakeoverTester()
    return tool.main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        sys.exit(1) 