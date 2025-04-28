"""DNS enumeration tool for RFS DNS Framework."""

from typing import Dict, List, Any, Optional, Set
import dns.resolver
import dns.zone
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .base_tool import BaseTool, ToolResult
from .utils import (
    resolve_domain,
    check_dnssec,
    is_wildcard_domain,
    get_domain_nameservers,
    parallel_dns_query,
    get_common_subdomains
)

TOOL_CONFIG = {
    'name': 'dns_enum',
    'description': 'DNS enumeration and reconnaissance',
    'critical': True,
    'requires_root': False,
    'order': 1
}

class DNSEnumTool(BaseTool):
    """DNS enumeration tool implementation."""
    
    def __init__(self):
        super().__init__(TOOL_CONFIG['name'], TOOL_CONFIG['description'])
        self.requires_root = TOOL_CONFIG['requires_root']
        self.critical = TOOL_CONFIG['critical']

    def validate_args(self, **kwargs) -> List[str]:
        """Validate tool arguments."""
        errors = []
        
        if not kwargs.get('domain'):
            errors.append("Domain is required")
            
        record_types = kwargs.get('record_types', '').split(',')
        valid_types = {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV'}
        invalid_types = set(record_types) - valid_types
        if invalid_types:
            errors.append(f"Invalid record types: {', '.join(invalid_types)}")
            
        return errors

    def run(self, domain: str, output_file: str, **kwargs) -> ToolResult:
        """Execute DNS enumeration."""
        start_time = datetime.now().isoformat()
        findings = []
        errors = []
        warnings = []
        raw_data = {
            'records': {},
            'nameservers': [],
            'dnssec': {},
            'subdomains': [],
            'wildcard': False
        }
        
        try:
            # Get record types to query
            record_types = kwargs.get('record_types', 'A,AAAA,CNAME,MX,NS,TXT,SOA').split(',')
            nameserver = kwargs.get('nameserver')
            check_wildcards = kwargs.get('check_wildcards', True)
            check_dnssec_enabled = kwargs.get('check_dnssec', True)
            wordlist = kwargs.get('wordlist')
            
            # Check for wildcard records
            if check_wildcards:
                raw_data['wildcard'] = is_wildcard_domain(domain, nameserver)
                if raw_data['wildcard']:
                    warnings.append("Domain uses wildcard DNS records")
                    findings.append(self.create_finding(
                        title="Wildcard DNS Records Detected",
                        description="The domain uses wildcard DNS records, which may affect enumeration accuracy",
                        risk_level="Low",
                        evidence={'wildcard_detected': True},
                        recommendations=[
                            "Review wildcard DNS configuration",
                            "Consider limiting wildcard scope for better security"
                        ]
                    ))
            
            # Get nameservers
            nameservers = get_domain_nameservers(domain)
            raw_data['nameservers'] = nameservers
            
            if not nameservers:
                warnings.append("Could not find authoritative nameservers")
            else:
                findings.append(self.create_finding(
                    title="Domain Nameservers",
                    description=f"Found {len(nameservers)} authoritative nameservers",
                    risk_level="Info",
                    evidence={'nameservers': nameservers}
                ))
            
            # Query DNS records
            results = parallel_dns_query(
                [domain],
                record_types,
                nameserver,
                max_workers=10
            )
            raw_data['records'] = results.get(domain, {})
            
            # Analyze records for security issues
            self._analyze_records(domain, raw_data['records'], findings)
            
            # Check DNSSEC
            if check_dnssec_enabled:
                dnssec_info = check_dnssec(domain)
                raw_data['dnssec'] = dnssec_info
                
                if not dnssec_info.get('enabled'):
                    findings.append(self.create_finding(
                        title="DNSSEC Not Enabled",
                        description="Domain does not have DNSSEC enabled",
                        risk_level="Medium",
                        recommendations=[
                            "Enable DNSSEC for improved DNS security",
                            "Implement proper key management for DNSSEC"
                        ]
                    ))
                else:
                    findings.append(self.create_finding(
                        title="DNSSEC Configuration",
                        description="Domain has DNSSEC enabled and properly configured",
                        risk_level="Info",
                        evidence=dnssec_info
                    ))
            
            # Enumerate subdomains
            if wordlist:
                subdomains = get_common_subdomains(domain, wordlist)
                raw_data['subdomains'] = list(subdomains)
                
                if subdomains:
                    findings.append(self.create_finding(
                        title="Subdomain Enumeration",
                        description=f"Found {len(subdomains)} subdomains",
                        risk_level="Info",
                        evidence={'subdomains': list(subdomains)}
                    ))
            
            success = True
            
        except Exception as e:
            success = False
            errors.append(f"DNS enumeration failed: {str(e)}")
        
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

    def _analyze_records(self, domain: str, records: Dict[str, List[str]], findings: List[Dict[str, Any]]) -> None:
        """Analyze DNS records for security issues."""
        
        # Check for SPF records
        txt_records = records.get('TXT', [])
        has_spf = any('v=spf1' in record.lower() for record in txt_records)
        
        if not has_spf:
            findings.append(self.create_finding(
                title="Missing SPF Record",
                description="Domain does not have an SPF record configured",
                risk_level="Medium",
                recommendations=[
                    "Configure SPF record to prevent email spoofing",
                    "Define authorized mail servers in SPF record"
                ]
            ))
        
        # Check for DMARC record
        try:
            dmarc_records = resolve_domain(f"_dmarc.{domain}", 'TXT')
            has_dmarc = any('v=dmarc1' in record.lower() for record in dmarc_records)
            
            if not has_dmarc:
                findings.append(self.create_finding(
                    title="Missing DMARC Record",
                    description="Domain does not have a DMARC record configured",
                    risk_level="Medium",
                    recommendations=[
                        "Configure DMARC record for email authentication",
                        "Start with monitoring policy before enforcement"
                    ]
                ))
        except:
            pass
        
        # Check for dangling CNAME records
        cname_records = records.get('CNAME', [])
        for cname in cname_records:
            try:
                if not resolve_domain(cname, 'A'):
                    findings.append(self.create_finding(
                        title="Dangling CNAME Record",
                        description=f"CNAME record points to non-existent domain: {cname}",
                        risk_level="High",
                        evidence={'cname': cname},
                        recommendations=[
                            "Remove or update dangling CNAME record",
                            "Regularly audit DNS records for validity"
                        ]
                    ))
            except:
                continue
        
        # Check for exposed internal names
        internal_patterns = ['.local', '.internal', '.corp', '.lan']
        for record_type, values in records.items():
            for value in values:
                if any(pattern in value.lower() for pattern in internal_patterns):
                    findings.append(self.create_finding(
                        title="Exposed Internal Hostname",
                        description=f"DNS record contains internal hostname: {value}",
                        risk_level="Medium",
                        evidence={'record_type': record_type, 'value': value},
                        recommendations=[
                            "Remove exposed internal hostnames from public DNS",
                            "Use separate internal/external DNS zones"
                        ]
                    ))

def main():
    """Tool entry point."""
    tool = DNSEnumTool()
    return tool 