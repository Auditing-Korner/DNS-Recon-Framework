#!/usr/bin/env python3

import json
import requests
import argparse
from collections import defaultdict
from typing import Dict, List, Optional, Union, Set, Tuple
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

class CloudProviderEnumerator:
    def __init__(self, providers_file: str = "page/providers.json"):
        self.providers_file = providers_file
        self.providers_data = self._load_providers()
        self.console = Console()
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 2
        self.dns_resolver.lifetime = 2

    def _load_providers(self) -> dict:
        """Load cloud providers data from JSON file."""
        try:
            with open(self.providers_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: {self.providers_file} not found")
            return {"cloud_providers": []}
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {self.providers_file}")
            return {"cloud_providers": []}

    def get_provider(self, provider_name: str) -> Optional[dict]:
        """Get a specific provider by name."""
        provider_name = provider_name.lower()
        for provider in self.providers_data.get("cloud_providers", []):
            if provider["name"].lower() == provider_name:
                return provider
        return None

    def get_providers_by_category(self) -> Dict[str, List[str]]:
        """Group providers by their category."""
        categories = defaultdict(list)
        for provider in self.providers_data.get("cloud_providers", []):
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

        for provider in self.providers_data.get("cloud_providers", []):
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
                answers = self.dns_resolver.resolve(domain, record_type)
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
                    self.dns_resolver.resolve(subdomain, 'A')
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
                self.dns_resolver.resolve(domain, 'A')
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
        for provider in self.providers_data.get("cloud_providers", []):
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
        global_count = sum(1 for p in self.providers_data.get("cloud_providers", []) if p.get("global"))
        total_count = len(self.providers_data.get("cloud_providers", []))
        
        rprint(f"\n[bold]Global vs Regional Split:[/bold]")
        rprint(f"Global Providers: {global_count}")
        rprint(f"Regional Providers: {total_count - global_count}")

def main():
    parser = argparse.ArgumentParser(description="Cloud Provider Enumeration Tool")
    parser.add_argument("-p", "--provider", help="Enumerate a specific cloud provider")
    parser.add_argument("-l", "--list", action="store_true", help="List all providers")
    parser.add_argument("-a", "--analyze", action="store_true", help="Show provider analysis")
    parser.add_argument("-d", "--dns", help="Show DNS information for a provider")
    parser.add_argument("-s", "--subdomains", help="Enumerate subdomains for a provider's domains")
    parser.add_argument("-f", "--file", default="providers.json", help="Path to providers JSON file")
    args = parser.parse_args()

    enumerator = CloudProviderEnumerator(providers_file=args.file)
    
    if args.dns:
        print(f"\n=== DNS Information for {args.dns} ===\n")
        enumerator.display_dns_info(args.dns)
    elif args.subdomains:
        provider = enumerator.get_provider(args.subdomains)
        if provider and provider.get('dns_domains'):
            print(f"\n=== Subdomain Enumeration for {args.subdomains} ===\n")
            for domain in provider['dns_domains']:
                subdomains = enumerator.enumerate_subdomains(domain)
                if subdomains:
                    print(f"\nDiscovered subdomains for {domain}:")
                    for subdomain in sorted(subdomains):
                        print(f"  - {subdomain}")
                else:
                    print(f"\nNo subdomains discovered for {domain}")
        else:
            print(f"Error: Provider '{args.subdomains}' not found or has no DNS domains configured.")
    elif args.provider:
        print(f"\n=== Cloud Provider Details: {args.provider} ===\n")
        enumerator.display_single_provider(args.provider)
    elif args.list:
        print("\n=== Cloud Provider Services Enumeration ===\n")
        enumerator.display_provider_info()
    elif args.analyze:
        print("\n=== Provider Analysis ===\n")
        enumerator.analyze_providers()
    else:
        # Default behavior: show all information
        print("\n=== Cloud Provider Services Enumeration ===\n")
        enumerator.display_provider_info()
        
        print("\n=== Provider Analysis ===\n")
        enumerator.analyze_providers()
        
        print("\n=== Detailed Provider Cards ===\n")
        enumerator.display_provider_cards()

if __name__ == "__main__":
    main() 