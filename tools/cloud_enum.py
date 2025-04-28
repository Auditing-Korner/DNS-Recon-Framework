"""Cloud resource enumeration tool for RFS DNS Framework."""

import dns.resolver
import dns.name
import dns.exception
import logging
import re
from typing import Dict, List, Optional, Any, Set
from .base_tool import BaseTool
import ipaddress

# Tool configuration
TOOL_CONFIG = {
    'name': 'cloud_enum',
    'description': 'Cloud resource enumeration tool',
    'critical': False,
    'requires_root': False,
    'order': 6
}

class CloudEnumTool(BaseTool):
    """Tool for enumerating cloud resources associated with a domain."""
    
    def __init__(self):
        super().__init__(TOOL_CONFIG['name'], TOOL_CONFIG['description'])
        self.requires_root = TOOL_CONFIG['requires_root']
        self.critical = TOOL_CONFIG['critical']
        self.findings = []
        
        # Cloud service patterns
        self.cloud_patterns = {
            'aws': {
                'domains': [
                    r'\.s3\.amazonaws\.com$',
                    r'\.cloudfront\.net$',
                    r'\.elb\.amazonaws\.com$',
                    r'\.elasticbeanstalk\.com$',
                    r'\.awsglobalaccelerator\.com$'
                ],
                'services': {
                    's3': r'\.s3\.amazonaws\.com$',
                    'cloudfront': r'\.cloudfront\.net$',
                    'elb': r'\.elb\.amazonaws\.com$',
                    'elasticbeanstalk': r'\.elasticbeanstalk\.com$',
                    'globalaccelerator': r'\.awsglobalaccelerator\.com$'
                }
            },
            'azure': {
                'domains': [
                    r'\.azurewebsites\.net$',
                    r'\.blob\.core\.windows\.net$',
                    r'\.azure-api\.net$',
                    r'\.azurecontainer\.io$',
                    r'\.azureedge\.net$'
                ],
                'services': {
                    'web_apps': r'\.azurewebsites\.net$',
                    'storage': r'\.blob\.core\.windows\.net$',
                    'api_management': r'\.azure-api\.net$',
                    'container': r'\.azurecontainer\.io$',
                    'cdn': r'\.azureedge\.net$'
                }
            },
            'gcp': {
                'domains': [
                    r'\.appspot\.com$',
                    r'\.googleapis\.com$',
                    r'\.run\.app$',
                    r'\.cloudfunctions\.net$',
                    r'\.storage\.googleapis\.com$'
                ],
                'services': {
                    'app_engine': r'\.appspot\.com$',
                    'apis': r'\.googleapis\.com$',
                    'cloud_run': r'\.run\.app$',
                    'functions': r'\.cloudfunctions\.net$',
                    'storage': r'\.storage\.googleapis\.com$'
                }
            }
        }

    def validate_args(self, args: Dict[str, Any]) -> bool:
        """
        Validate tool arguments.
        
        Args:
            args: Tool arguments
            
        Returns:
            bool: True if arguments are valid
        """
        if not args.get('domain'):
            logging.error('Domain argument is required')
            return False
        return True

    def check_cloud_association(self, domain: str, record_type: str = 'CNAME') -> List[Dict[str, Any]]:
        """
        Check if a domain is associated with cloud services.
        
        Args:
            domain: Domain to check
            record_type: DNS record type to check (default: CNAME)
            
        Returns:
            List[Dict[str, Any]]: List of cloud service associations found
        """
        findings = []
        
        try:
            logging.info(f"Checking {record_type} records for {domain}")
            answers = dns.resolver.resolve(domain, record_type)
            
            for rdata in answers:
                target = str(rdata.target if record_type == 'CNAME' else rdata).rstrip('.')
                logging.debug(f"Found {record_type} record: {target}")
                
                # Check against each cloud provider's patterns
                for provider, data in self.cloud_patterns.items():
                    for service, pattern in data['services'].items():
                        try:
                            if re.search(pattern, target, re.IGNORECASE):
                                finding = {
                                    'domain': domain,
                                    'target': target,
                                    'provider': provider,
                                    'service': service,
                                    'record_type': record_type,
                                    'description': f'Found {provider.upper()} {service} resource'
                                }
                                logging.info(f"Found cloud association: {finding['description']}")
                                findings.append(finding)
                        except re.error as e:
                            logging.error(f"Invalid regex pattern for {provider} {service}: {str(e)}")
                            
        except dns.resolver.NXDOMAIN:
            logging.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logging.debug(f"No {record_type} records found for {domain}")
        except dns.resolver.Timeout:
            logging.warning(f"DNS query timeout for {domain}")
        except dns.resolver.NoNameservers:
            logging.warning(f"No nameservers available for {domain}")
        except Exception as e:
            logging.error(f"Error checking {domain}: {str(e)}")
            
        return findings

    def check_ip_ranges(self, domain: str) -> List[Dict[str, Any]]:
        """
        Check if domain IP addresses belong to cloud provider ranges.
        
        Args:
            domain: Domain to check
            
        Returns:
            List[Dict[str, Any]]: List of cloud IP range matches
        """
        findings = []
        
        # Cloud provider IP ranges
        # These are example ranges - in production, these should be regularly updated
        cloud_ranges = {
            'aws': [
                '3.0.0.0/15',
                '3.2.0.0/24',
                '13.32.0.0/15',
                '13.35.0.0/16',
                '52.95.245.0/24',
                '54.240.0.0/18'
            ],
            'azure': [
                '13.64.0.0/11',
                '13.96.0.0/13',
                '13.104.0.0/14',
                '20.33.0.0/16',
                '20.34.0.0/15',
                '20.36.0.0/14'
            ],
            'gcp': [
                '8.8.4.0/24',
                '8.8.8.0/24',
                '34.64.0.0/10',
                '34.128.0.0/10',
                '35.184.0.0/13',
                '35.192.0.0/14'
            ]
        }
        
        try:
            logging.info(f"Checking IP ranges for {domain}")
            answers = dns.resolver.resolve(domain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                logging.debug(f"Found IP: {ip}")
                
                # Check each provider's ranges
                for provider, ranges in cloud_ranges.items():
                    for ip_range in ranges:
                        try:
                            network = ipaddress.ip_network(ip_range)
                            if ipaddress.ip_address(ip) in network:
                                finding = {
                                    'domain': domain,
                                    'ip': ip,
                                    'provider': provider,
                                    'ip_range': ip_range,
                                    'description': f'IP address belongs to {provider.upper()} range'
                                }
                                logging.info(f"Found IP in cloud range: {finding['description']}")
                                findings.append(finding)
                                break  # Found a match, no need to check other ranges for this provider
                        except ValueError as e:
                            logging.error(f"Invalid IP or network: {str(e)}")
                
        except dns.resolver.NXDOMAIN:
            logging.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logging.debug(f"No A records found for {domain}")
        except dns.resolver.Timeout:
            logging.warning(f"DNS query timeout for {domain}")
        except dns.resolver.NoNameservers:
            logging.warning(f"No nameservers available for {domain}")
        except Exception as e:
            logging.error(f"Error checking IP ranges for {domain}: {str(e)}")
            
        return findings

    def run(self, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run the cloud enumeration scan.
        
        Args:
            args: Tool arguments including domain to scan
            
        Returns:
            List[Dict[str, Any]]: List of findings
        """
        domain = args['domain']
        subdomains = args.get('subdomains', [])
        
        if not subdomains:
            # If no subdomains provided, at least check the main domain
            subdomains = [domain]
        
        # Track unique findings to avoid duplicates
        seen_findings = set()
        
        for subdomain in subdomains:
            # Check CNAME records
            cname_findings = self.check_cloud_association(subdomain, 'CNAME')
            for finding in cname_findings:
                finding_key = f"{finding['domain']}:{finding['provider']}:{finding['service']}"
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    self.findings.append(finding)
            
            # Check A records
            a_findings = self.check_cloud_association(subdomain, 'A')
            for finding in a_findings:
                finding_key = f"{finding['domain']}:{finding['provider']}:{finding['service']}"
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    self.findings.append(finding)
            
            # Check IP ranges
            ip_findings = self.check_ip_ranges(subdomain)
            for finding in ip_findings:
                finding_key = f"{finding['domain']}:{finding['provider']}:{finding['service']}"
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    self.findings.append(finding)
        
        return self.findings

def main():
    """Main function for standalone usage."""
    tool = CloudEnumTool()
    args = {'domain': 'example.com'}
    findings = tool.run(args)
    for finding in findings:
        print(f"[{finding['provider'].upper()}] {finding['description']}")
        print(f"Domain: {finding['domain']}")
        print(f"Service: {finding['service']}")
        print(f"Target: {finding['target']}")
        print("---")

if __name__ == '__main__':
    main() 