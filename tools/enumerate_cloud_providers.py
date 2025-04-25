#!/usr/bin/env python3

import json
import requests
import dns.resolver
import dns.exception
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress
import sys
import os
from typing import Dict, List, Optional, Union, Set, Tuple, Any
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from .base_tool import BaseTool, ToolResult
    from .utils import check_operation_requirements
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult
    from tools.utils import check_operation_requirements

class CloudEnumerator(BaseTool):
    """Cloud Provider Detection and Analysis Tool"""
    
    def __init__(self):
        super().__init__(
            name="cloud_enum",
            description="Cloud Provider Enumeration Tool"
        )
        self.version = "2.1.0"
        self.providers = self._load_providers()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        self.console = Console()
        
        # Check if we have necessary permissions for DNS operations
        self._check_permissions()

    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run cloud enumeration with provided arguments"""
        domain = self.get_param('domain')
        providers_to_check = self.get_param('providers', 'all').split(',')
        analyze_mode = self.get_param('analyze', False)
        timeout = self.get_param('timeout', 5)
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        try:
            # Check dependencies
            deps_ok, error_msg = self.check_dependencies()
            if not deps_ok:
                result.add_error(error_msg)
                return
            
            # Analyze domain
            self.analyze_domain(domain, analyze_mode, result)
            
            # Add risk summary
            risk_summary = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            }
            for finding in result.findings:
                risk_summary[finding.get('risk_level', 'Info')] += 1
            result.metadata['risk_summary'] = risk_summary
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during analysis: {str(e)}")
            
    def analyze_domain(self, domain: str, analyze: bool = False, result: ToolResult = None) -> None:
        """Analyze a domain for cloud provider usage"""
        if result is None:
            result = ToolResult(
                success=True,
                tool_name=self.name,
                findings=[]
            )
        
        try:
            # Resolve domain
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Get A records
            try:
                a_records = resolver.resolve(domain, 'A')
                ips = [str(r) for r in a_records]
            except dns.exception.DNSException:
                ips = []
                result.add_warning(f"Could not resolve A records for {domain}")
            
            # Get CNAME records
            try:
                cname_records = resolver.resolve(domain, 'CNAME')
                cnames = [str(r.target).rstrip('.') for r in cname_records]
            except dns.exception.DNSException:
                cnames = []
                result.add_warning(f"Could not resolve CNAME records for {domain}")
            
            # Check each provider
            for provider_name, provider_info in self.providers.items():
                # Check IP ranges
                for ip in ips:
                    for ip_range in provider_info.get('ip_ranges', []):
                        try:
                            if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                                result.add_finding({
                                    'title': f"Domain hosted on {provider_name}",
                                    'description': f"IP address {ip} belongs to {provider_name} range {ip_range}",
                                    'risk_level': "Info",
                                    'details': {
                                        'provider': provider_name,
                                        'ip_address': ip,
                                        'ip_range': ip_range,
                                        'domain': domain
                                    }
                                })
                                break
                        except ValueError:
                            continue
                
                # Check CNAME patterns
                for cname in cnames:
                    for pattern in provider_info.get('cname_patterns', []):
                        if pattern.lower() in cname.lower():
                            result.add_finding({
                                'title': f"Domain using {provider_name} services",
                                'description': f"CNAME record matches {provider_name} pattern",
                                'risk_level': "Info",
                                'details': {
                                    'provider': provider_name,
                                    'cname': cname,
                                    'pattern': pattern,
                                    'domain': domain
                                }
                            })
                            break
            
            # Perform detailed analysis if requested
            if analyze:
                for finding in result.findings:
                    provider = finding.get('details', {}).get('provider')
                    if provider in self.providers:
                        self._analyze_provider(domain, provider, self.providers[provider], result)
            
        except Exception as e:
            result.add_error(f"Error analyzing domain: {str(e)}")
            
    def _analyze_provider(self, domain: str, provider: str, provider_info: Dict, result: ToolResult) -> None:
        """Perform detailed analysis of a detected provider"""
        try:
            # Check for common misconfigurations
            for check in provider_info.get('security_checks', []):
                try:
                    if check['type'] == 'http':
                        response = requests.get(
                            check['url'].format(domain=domain),
                            timeout=5,
                            allow_redirects=False
                        )
                        if check.get('status_code') and response.status_code == check['status_code']:
                            result.add_finding({
                                'title': f"{provider} Security Issue",
                                'description': check['description'],
                                'risk_level': check['risk_level'],
                                'details': {
                                    'provider': provider,
                                    'url': response.url,
                                    'status_code': response.status_code,
                                    'domain': domain
                                }
                            })
                    elif check['type'] == 'dns':
                        records = dns.resolver.resolve(
                            check['query'].format(domain=domain),
                            check.get('record_type', 'A')
                        )
                        if any(check['pattern'] in str(r) for r in records):
                            result.add_finding({
                                'title': f"{provider} DNS Issue",
                                'description': check['description'],
                                'risk_level': check['risk_level'],
                                'details': {
                                    'provider': provider,
                                    'query': check['query'],
                                    'pattern': check['pattern'],
                                    'domain': domain
                                }
                            })
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error analyzing {provider}: {str(e)}")

    def _check_permissions(self):
        """Check if we have necessary permissions for DNS operations"""
        has_perms, error_msg = check_operation_requirements('low_port')
        if not has_perms:
            self.console.print(f"[yellow]Warning: {error_msg}")
            self.console.print("[yellow]Using standard DNS resolution methods")
            # Use system resolver as fallback
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def _load_providers(self) -> dict:
        """Load cloud provider definitions"""
        try:
            provider_file = Path(__file__).parent / 'providers.json'
            with open(provider_file) as f:
                return json.load(f)
        except Exception as e:
            self.console.print(f"[red]Error loading providers: {str(e)}")
            return {}

    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if required dependencies are available"""
        try:
            import dns.resolver
            import requests
            return True, None
        except ImportError as e:
            return False, f"Missing dependency: {str(e)}"

    def get_provider(self, provider_name: str) -> Optional[dict]:
        """Get a specific provider by name."""
        provider_name = provider_name.lower()
        return self.providers.get(provider_name)

    def get_providers_by_category(self) -> Dict[str, List[str]]:
        """Group providers by their category."""
        categories = defaultdict(list)
        for provider in self.providers.values():
            categories[provider.get("category", "Unknown")].append(provider["name"])
        return dict(categories)

    def fetch_ip_ranges(self, provider: dict) -> Optional[List[str]]:
        """Fetch IP ranges for a provider if available."""
        if not provider.get("ip_ranges"):
            return None
        
        try:
            response = requests.get(provider["ip_ranges"], timeout=10)
            if response.status_code == 200:
                return [str(response.url)]  # Return the URL as successful fetch
            return None
        except requests.RequestException:
            return None

    def resolve_asn_info(self, asn: Optional[str]) -> Optional[str]:
        """Resolve ASN information using DNS."""
        if not asn:
            return None
        
        try:
            # Remove 'AS' prefix if present
            asn_number = asn.replace("AS", "")
            query = f"AS{asn_number}.asn.cymru.com"
            answers = dns.resolver.resolve(query, "TXT")
            return str(answers[0]).strip('"')
        except Exception:
            return None

    def display_provider_info(self):
        """Display cloud provider information in a formatted table."""
        table = Table(title="Cloud Provider Services")
        table.add_column("Provider Name", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Global", style="yellow")
        table.add_column("ASN", style="magenta")
        table.add_column("IP Ranges", style="blue")
        table.add_column("Logo URL", style="white", overflow="fold")

        for provider in self.providers.values():
            ip_ranges = "Yes" if provider.get("ip_ranges") else "No"
            global_status = "✓" if provider.get("global") else "✗"
            logo_url = provider.get("logo", "N/A")
            
            table.add_row(
                provider["name"],
                provider.get("category", "Unknown"),
                global_status,
                ", ".join(provider.get("asn", ["N/A"])) if isinstance(provider.get("asn"), list) else str(provider.get("asn", "N/A")),
                ip_ranges,
                logo_url
            )

        self.console.print(table)

    def check_domain_records(self, domain: str) -> Dict[str, List[str]]:
        """Check various DNS records for a domain."""
        records = defaultdict(list)
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except Exception as e:
                records[record_type] = [f"Error: {str(e)}"]
        
        return dict(records)

    def enumerate_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> Set[str]:
        """Enumerate subdomains for a given domain using DNS."""
        if wordlist is None:
            # Basic common subdomain prefixes
            wordlist = ['www', 'api', 'mail', 'remote', 'blog', 'dev', 'stage', 
                       'test', 'admin', 'portal', 'cloud', 'services']
        
        discovered_subdomains = set()
        
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Enumerating subdomains for {domain}...", total=len(wordlist))
            
            def check_subdomain(prefix: str) -> Optional[str]:
                subdomain = f"{prefix}.{domain}"
                try:
                    self.resolver.resolve(subdomain, 'A')
                    return subdomain
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_subdomain = {
                    executor.submit(check_subdomain, prefix): prefix 
                    for prefix in wordlist
                }
                
                for future in as_completed(future_to_subdomain):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        discovered_subdomains.add(result)
        
        return discovered_subdomains

    def validate_provider_domains(self, provider: dict) -> Dict[str, bool]:
        """Validate all domains for a provider."""
        results = {}
        domains = provider.get('dns_domains', [])
        
        for domain in domains:
            try:
                self.resolver.resolve(domain, 'A')
                results[domain] = True
            except:
                results[domain] = False
        
        return results

    def display_dns_info(self, provider_name: str):
        """Display detailed DNS information for a provider."""
        provider = self.get_provider(provider_name)
        if not provider:
            self.console.print(f"[red]Error: Provider '{provider_name}' not found.[/red]")
            return

        # Create DNS information table
        dns_table = Table(title=f"DNS Information for {provider['name']}")
        dns_table.add_column("Domain", style="cyan")
        dns_table.add_column("Status", style="green")
        dns_table.add_column("Records", style="yellow", overflow="fold")

        domains = provider.get('dns_domains', [])
        if not domains:
            self.console.print("[yellow]No DNS domains configured for this provider.[/yellow]")
            return

        for domain in domains:
            # Check domain validity
            try:
                records = self.check_domain_records(domain)
                status = "[green]Active[/green]"
                records_str = "\n".join([f"{k}: {', '.join(v)}" for k, v in records.items() if v])
            except Exception:
                status = "[red]Inactive[/red]"
                records_str = "N/A"
            
            dns_table.add_row(domain, status, records_str)

        self.console.print(dns_table)

    def display_single_provider(self, provider_name: str):
        """Display detailed information for a single provider."""
        provider = self.get_provider(provider_name)
        if not provider:
            self.console.print(f"[red]Error: Provider '{provider_name}' not found.[/red]")
            return

        # Fetch additional information
        asn_info = self.resolve_asn_info(provider.get("asn"))
        ip_ranges = self.fetch_ip_ranges(provider)

        # Create detailed card
        card = f"""# {provider['name']}

![Logo]({provider.get('logo', '')})

## Basic Information
- **Category:** {provider.get('category', 'Unknown')}
- **Website:** {provider['website']}
- **Global:** {'Yes' if provider.get('global') else 'No'}

## Technical Details
- **ASN:** {provider.get('asn', 'N/A')}
- **ASN Info:** {asn_info if asn_info else 'N/A'}
- **IP Ranges Available:** {'Yes' if provider.get('ip_ranges') else 'No'}
- **IP Ranges URL:** {provider.get('ip_ranges', 'N/A')}

## DNS Domains
"""
        # Add DNS domains information
        domains = provider.get('dns_domains', [])
        if domains:
            card += "\n".join([f"- {domain}" for domain in domains])
        else:
            card += "- No DNS domains configured"

        card += "\n\n## Additional Information"
        card += f"\n- **Description:** {provider.get('description', 'No description available')}"
        card += f"\n- **Services:** {', '.join(provider.get('services', ['N/A']))}"

        self.console.print(Panel(Markdown(card), title=provider['name'], subtitle="Cloud Provider Details"))

        # Display DNS information in a separate table
        if domains:
            print("\n=== DNS Information ===\n")
            self.display_dns_info(provider_name)

    def display_provider_cards(self):
        """Display detailed provider cards with logos."""
        for provider in self.providers.values():
            card = f"""
# {provider['name']}

![Logo]({provider.get('logo', '')})

- **Category:** {provider.get('category', 'Unknown')}
- **Website:** {provider['website']}
- **Global:** {'Yes' if provider.get('global') else 'No'}
- **ASN:** {provider.get('asn', 'N/A')}
- **IP Ranges Available:** {'Yes' if provider.get('ip_ranges') else 'No'}
"""
            self.console.print(Markdown(card))
            print("\n---\n")

    def analyze_providers(self):
        """Perform analysis on cloud providers."""
        # Count providers by category
        categories = self.get_providers_by_category()
        
        # Display category statistics
        stats_table = Table(title="Cloud Provider Statistics")
        stats_table.add_column("Category", style="cyan")
        stats_table.add_column("Count", style="green")
        
        for category, providers in categories.items():
            stats_table.add_row(category, str(len(providers)))
        
        self.console.print(stats_table)
        
        # Display global vs regional split
        global_count = sum(1 for p in self.providers.values() if p.get("global"))
        total_count = len(self.providers)
        
        rprint(f"\n[bold]Global vs Regional Split:[/bold]")
        rprint(f"Global Providers: {global_count}")
        rprint(f"Regional Providers: {total_count - global_count}")

    def _check_nameservers(self, domain: str) -> List[Tuple[str, float]]:
        matches = []
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_str = str(ns).lower()
                for provider_name, provider in self.providers.items():
                    for pattern in provider['nameservers']:
                        if pattern.lower() in ns_str:
                            matches.append((provider_name, 0.8))
        except Exception:
            pass
        return matches

    def _check_cnames(self, domain: str) -> List[Tuple[str, float]]:
        matches = []
        try:
            cname_records = self.resolver.resolve(domain, 'CNAME')
            for cname in cname_records:
                cname_str = str(cname).lower()
                for provider_name, provider in self.providers.items():
                    for pattern in provider['cnames']:
                        if pattern.lower() in cname_str:
                            matches.append((provider_name, 0.9))
        except Exception:
            pass
        return matches

    def _check_ip_ranges(self, domain: str) -> List[Tuple[str, float]]:
        matches = []
        try:
            a_records = self.resolver.resolve(domain, 'A')
            for record in a_records:
                ip = ipaddress.ip_address(str(record))
                for provider_name, provider in self.providers.items():
                    for ip_range in provider['ip_ranges']:
                        try:
                            if ip in ipaddress.ip_network(ip_range):
                                matches.append((provider_name, 0.7))
                        except ValueError:
                            continue
        except Exception:
            pass
        return matches

    def display_domain_analysis(self, domain: str) -> None:
        """
        Analyze a domain and display the results in a formatted way.
        """
        print(f"\nAnalyzing cloud provider usage for: {domain}")
        print("-" * 50)
        
        results = self.analyze_domain(domain)
        
        if not results:
            print("Could not determine hosting provider. The domain might be:")
            print("- Using a traditional hosting provider")
            print("- Using an unlisted cloud provider")
            print("- Having DNS resolution issues")
            return

        print("Detected cloud providers:")
        for provider, confidence in sorted(results.items(), key=lambda x: x[1], reverse=True):
            confidence_pct = int(confidence * 100)
            provider_info = self.providers.get(provider, {})
            category = provider_info.get('category', 'Unknown')
            website = provider_info.get('website', 'N/A')
            
            print(f"\n{provider} ({category})")
            print(f"Confidence: {confidence_pct}%")
            print(f"Website: {website}")

    def main(self):
        """Entry point for cloud enumeration tool"""
        self._run_tool(self.get_params(), self.get_result())
        return self.get_result()

def main():
    """Entry point for cloud enumeration tool"""
    tool = CloudEnumerator()
    return tool.main()

if __name__ == "__main__":
    main() 