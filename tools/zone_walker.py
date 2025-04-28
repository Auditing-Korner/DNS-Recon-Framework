"""DNS zone transfer and walking tool for RFS DNS Framework."""

from typing import Dict, List, Any, Optional, Set
import dns.zone
import dns.query
import dns.resolver
import dns.name
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .base_tool import BaseTool, ToolResult
from .utils import (
    check_zone_transfer,
    get_domain_nameservers,
    resolve_domain,
    parallel_dns_query
)

TOOL_CONFIG = {
    'name': 'zone_walker',
    'description': 'DNS zone transfer and walking',
    'critical': True,
    'requires_root': False,
    'order': 3
}

class ZoneWalkerTool(BaseTool):
    """DNS zone walking tool implementation."""
    
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
        """Execute zone walking."""
        start_time = datetime.now().isoformat()
        findings = []
        errors = []
        warnings = []
        raw_data = {
            'zone_transfers': {},
            'records': {},
            'nameservers': [],
            'subzones': []
        }
        
        try:
            # Get tool parameters
            record_types = kwargs.get('record_types', 'A,AAAA,CNAME,MX,NS,TXT,SOA').split(',')
            nameserver = kwargs.get('nameserver')
            
            # Get nameservers
            nameservers = get_domain_nameservers(domain)
            raw_data['nameservers'] = nameservers
            
            if not nameservers:
                warnings.append("Could not find authoritative nameservers")
            
            # Try zone transfers
            for ns in nameservers:
                try:
                    zone = check_zone_transfer(domain, ns)
                    if zone:
                        raw_data['zone_transfers'][ns] = self._process_zone(zone)
                        findings.append(self.create_finding(
                            title="Zone Transfer Allowed",
                            description=f"DNS server {ns} allows zone transfers",
                            risk_level="Critical",
                            evidence={
                                'nameserver': ns,
                                'records': len(raw_data['zone_transfers'][ns])
                            },
                            recommendations=[
                                "Disable zone transfers on DNS servers",
                                "Restrict zone transfers to specific IP addresses",
                                "Implement TSIG for secure zone transfers"
                            ]
                        ))
                except Exception as e:
                    errors.append(f"Zone transfer failed for {ns}: {str(e)}")
            
            # Walk the zone
            subzones = self._walk_zone(domain, nameserver)
            raw_data['subzones'] = list(subzones)
            
            if subzones:
                findings.append(self.create_finding(
                    title="Subzones Found",
                    description=f"Found {len(subzones)} subzones through zone walking",
                    risk_level="Info",
                    evidence={'subzones': list(subzones)}
                ))
            
            # Query records for each subzone
            all_zones = {domain} | subzones
            for zone in all_zones:
                results = parallel_dns_query(
                    [zone],
                    record_types,
                    nameserver,
                    max_workers=10
                )
                if results:
                    raw_data['records'][zone] = results[zone]
            
            # Analyze findings
            self._analyze_zone_security(raw_data, findings)
            
            success = True
            
        except Exception as e:
            success = False
            errors.append(f"Zone walking failed: {str(e)}")
        
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

    def _process_zone(self, zone: dns.zone.Zone) -> List[Dict[str, Any]]:
        """Process zone transfer data."""
        records = []
        
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                record = {
                    'name': str(name),
                    'ttl': rdataset.ttl,
                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                    'records': [str(rdata) for rdata in rdataset]
                }
                records.append(record)
        
        return records

    def _walk_zone(self, domain: str, nameserver: Optional[str] = None) -> Set[str]:
        """Walk a DNS zone to discover subzones."""
        subzones = set()
        
        try:
            # Get SOA record to confirm zone exists
            soa = resolve_domain(domain, 'SOA', nameserver)
            if not soa:
                return subzones
            
            # Get NS records for potential subzones
            ns_records = resolve_domain(domain, 'NS', nameserver)
            if not ns_records:
                return subzones
            
            # Common subzone prefixes to try
            prefixes = [
                'www', 'mail', 'remote', 'blog', 'webmail',
                'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn',
                'api', 'dev', 'staging', 'app', 'admin'
            ]
            
            # Try each prefix
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_prefix = {
                    executor.submit(
                        self._check_subzone,
                        f"{prefix}.{domain}",
                        nameserver
                    ): prefix
                    for prefix in prefixes
                }
                
                for future in as_completed(future_to_prefix):
                    try:
                        result = future.result()
                        if result:
                            subzones.add(result)
                    except:
                        continue
            
            # Try to find more subzones from discovered ones
            new_subzones = set()
            for subzone in subzones:
                try:
                    ns_records = resolve_domain(subzone, 'NS', nameserver)
                    if ns_records:
                        new_subzones.update(
                            self._walk_zone(subzone, nameserver)
                        )
                except:
                    continue
            
            subzones.update(new_subzones)
            
        except Exception:
            pass
        
        return subzones

    def _check_subzone(self, domain: str, nameserver: Optional[str] = None) -> Optional[str]:
        """Check if a domain is a valid subzone."""
        try:
            # Check for NS records
            ns_records = resolve_domain(domain, 'NS', nameserver)
            if ns_records:
                return domain
                
            # Check for SOA record
            soa_records = resolve_domain(domain, 'SOA', nameserver)
            if soa_records:
                return domain
        except:
            pass
        
        return None

    def _analyze_zone_security(
        self,
        raw_data: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze zone security configuration."""
        
        # Check for zone transfer findings
        if raw_data['zone_transfers']:
            findings.append(self.create_finding(
                title="Multiple Zone Transfers Allowed",
                description=f"Multiple DNS servers allow zone transfers: {', '.join(raw_data['zone_transfers'].keys())}",
                risk_level="Critical",
                evidence={'servers': list(raw_data['zone_transfers'].keys())},
                recommendations=[
                    "Immediately disable zone transfers on all servers",
                    "Implement proper access controls for zone transfers",
                    "Use TSIG or similar for secure zone transfers"
                ]
            ))
        
        # Analyze record patterns
        for zone, records in raw_data['records'].items():
            # Check for sensitive subdomains
            sensitive_patterns = [
                'internal', 'private', 'secret', 'admin',
                'test', 'dev', 'staging', 'uat', 'qa'
            ]
            
            for pattern in sensitive_patterns:
                if pattern in zone:
                    findings.append(self.create_finding(
                        title="Sensitive Subdomain Exposed",
                        description=f"Potentially sensitive subdomain found: {zone}",
                        risk_level="Medium",
                        evidence={'domain': zone, 'pattern': pattern},
                        recommendations=[
                            "Review necessity of exposing sensitive subdomains",
                            "Consider using internal DNS for non-public resources",
                            "Implement proper access controls"
                        ]
                    ))
            
            # Check for potentially dangerous records
            for record_type, values in records.items():
                if record_type in ['A', 'AAAA']:
                    for ip in values:
                        if any(p in ip for p in ['10.', '172.16.', '192.168.']):
                            findings.append(self.create_finding(
                                title="Internal IP Address Exposed",
                                description=f"DNS record contains internal IP address: {ip}",
                                risk_level="Medium",
                                evidence={
                                    'zone': zone,
                                    'record_type': record_type,
                                    'ip': ip
                                },
                                recommendations=[
                                    "Remove internal IP addresses from public DNS",
                                    "Use split-horizon DNS if internal resolution is needed"
                                ]
                            ))

def main():
    """Tool entry point."""
    tool = ZoneWalkerTool()
    return tool 