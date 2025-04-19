#!/usr/bin/env python3

import json
import requests
from collections import defaultdict
from typing import Dict, List, Optional
import dns.resolver
import ipaddress
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.markdown import Markdown

class CloudProviderEnumerator:
    def __init__(self, providers_file: str = "providers.json"):
        self.providers_file = providers_file
        self.providers_data = self._load_providers()
        self.console = Console()

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
                provider.get("asn", "N/A"),
                ip_ranges,
                logo_url
            )

        self.console.print(table)

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
    enumerator = CloudProviderEnumerator()
    
    print("\n=== Cloud Provider Services Enumeration ===\n")
    
    # Display detailed provider information
    enumerator.display_provider_info()
    
    print("\n=== Provider Analysis ===\n")
    
    # Display provider analysis
    enumerator.analyze_providers()
    
    print("\n=== Detailed Provider Cards ===\n")
    
    # Display provider cards with logos
    enumerator.display_provider_cards()

if __name__ == "__main__":
    main() 