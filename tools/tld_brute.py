"""TLD bruteforce tool for RFS DNS Framework."""

from typing import Dict, List, Any, Optional, Set
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
import os

from .base_tool import BaseTool, ToolResult
from .utils import (
    resolve_domain,
    is_domain_registered,
    parallel_dns_query
)

TOOL_CONFIG = {
    'name': 'tld_brute',
    'description': 'TLD bruteforcing and enumeration',
    'critical': False,
    'requires_root': False,
    'order': 4
}

class TLDBruteTool(BaseTool):
    """TLD bruteforce tool implementation."""
    
    def __init__(self):
        super().__init__(TOOL_CONFIG['name'], TOOL_CONFIG['description'])
        self.requires_root = TOOL_CONFIG['requires_root']
        self.critical = TOOL_CONFIG['critical']
        
        # Load TLD list
        self.tld_list = self._load_tld_list()

    def validate_args(self, **kwargs) -> List[str]:
        """Validate tool arguments."""
        errors = []
        
        if not kwargs.get('domain'):
            errors.append("Domain is required")
            
        if kwargs.get('custom_tlds'):
            try:
                custom_tlds = kwargs['custom_tlds'].split(',')
                if not all(tld.strip('.').isalnum() for tld in custom_tlds):
                    errors.append("Invalid TLD format in custom TLDs")
            except:
                errors.append("Invalid custom TLDs format")
                
        return errors

    def run(self, domain: str, output_file: str, **kwargs) -> ToolResult:
        """Execute TLD bruteforce."""
        start_time = datetime.now().isoformat()
        findings = []
        errors = []
        warnings = []
        raw_data = {
            'registered_domains': [],
            'dns_records': {},
            'similar_content': []
        }
        
        try:
            # Get base domain without TLD
            base_domain = domain.split('.')[0]
            
            # Get TLDs to check
            tlds_to_check = set(self.tld_list)
            if kwargs.get('custom_tlds'):
                tlds_to_check.update(kwargs['custom_tlds'].split(','))
            
            # Remove the original domain's TLD from the list
            original_tld = domain.split('.')[-1]
            tlds_to_check.discard(original_tld)
            
            # Check domain registration across TLDs
            registered_domains = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_tld = {
                    executor.submit(
                        self._check_domain_variation,
                        base_domain,
                        tld
                    ): tld
                    for tld in tlds_to_check
                }
                
                for future in as_completed(future_to_tld):
                    tld = future_to_tld[future]
                    try:
                        result = future.result()
                        if result:
                            registered_domains.append(result)
                    except Exception as e:
                        errors.append(f"Error checking .{tld}: {str(e)}")
            
            raw_data['registered_domains'] = registered_domains
            
            if registered_domains:
                findings.append(self.create_finding(
                    title="Domain Variations Found",
                    description=f"Found {len(registered_domains)} registered domain variations",
                    risk_level="Medium",
                    evidence={'domains': registered_domains},
                    recommendations=[
                        "Register important TLD variations to prevent typosquatting",
                        "Monitor registered variations for malicious activity",
                        "Consider trademark protection services"
                    ]
                ))
                
                # Check DNS records for registered domains
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
                for registered_domain in registered_domains:
                    results = parallel_dns_query(
                        [registered_domain],
                        record_types,
                        max_workers=5
                    )
                    if results:
                        raw_data['dns_records'][registered_domain] = results[registered_domain]
                        
                        # Check for similar DNS configurations
                        if self._check_similar_configuration(
                            results[registered_domain],
                            raw_data['dns_records'].get(domain, {})
                        ):
                            raw_data['similar_content'].append(registered_domain)
                            findings.append(self.create_finding(
                                title="Similar DNS Configuration Found",
                                description=f"Domain {registered_domain} has similar DNS configuration",
                                risk_level="High",
                                evidence={
                                    'domain': registered_domain,
                                    'records': results[registered_domain]
                                },
                                recommendations=[
                                    "Investigate potential domain squatting",
                                    "Consider legal action if trademark infringement found",
                                    "Monitor domain for malicious activity"
                                ]
                            ))
            
            success = True
            
        except Exception as e:
            success = False
            errors.append(f"TLD bruteforce failed: {str(e)}")
        
        end_time = datetime.now().isoformat()
        
        # Create and return result
        result = self.create_result(
            success=success,
            findings=findings,
            domain=domain,
            output_file=output_file,
            errors=errors,
            warnings=warnings,
            raw_data=raw_data,
            start_time=start_time,
            end_time=end_time
        )
        
        # Save results
        result.save_to_file()
        
        return result

    def _load_tld_list(self) -> List[str]:
        """Load list of TLDs to check."""
        common_tlds = [
            'com', 'net', 'org', 'info', 'biz', 'edu',
            'gov', 'mil', 'app', 'dev', 'io', 'ai',
            'co', 'me', 'us', 'uk', 'ca', 'au', 'de',
            'fr', 'es', 'it', 'nl', 'ru', 'cn', 'jp',
            'br', 'in', 'cloud', 'online', 'store', 'tech',
            'xyz', 'site', 'web', 'blog', 'app', 'dev'
        ]
        
        # Try to load additional TLDs from file
        tld_file = os.path.join(
            os.path.dirname(__file__),
            'data',
            'tlds.txt'
        )
        
        if os.path.exists(tld_file):
            try:
                with open(tld_file) as f:
                    return list(set(
                        tld.strip().lower()
                        for tld in f.readlines()
                        if tld.strip()
                    ))
            except:
                pass
        
        return common_tlds

    def _check_domain_variation(self, base_domain: str, tld: str) -> Optional[str]:
        """Check if a domain variation is registered."""
        variation = f"{base_domain}.{tld}"
        try:
            if is_domain_registered(variation):
                return variation
        except:
            pass
        return None

    def _check_similar_configuration(
        self,
        records1: Dict[str, List[str]],
        records2: Dict[str, List[str]]
    ) -> bool:
        """Check if two DNS configurations are similar."""
        if not records2:
            return False
            
        # Check for identical records
        for record_type in ['A', 'AAAA', 'MX']:
            if (
                record_type in records1 and
                record_type in records2 and
                set(records1[record_type]) == set(records2[record_type])
            ):
                return True
        
        return False

def main():
    """Tool entry point."""
    tool = TLDBruteTool()
    return tool 