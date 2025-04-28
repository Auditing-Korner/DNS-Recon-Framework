"""DNS Takeover vulnerability scanner for RFS DNS Framework."""

import dns.resolver
import dns.name
import dns.exception
import logging
from typing import Dict, List, Optional, Any
from .base_tool import BaseTool

# Tool configuration
TOOL_CONFIG = {
    'description': 'DNS takeover vulnerability scanner',
    'critical': True,
    'requires_root': False,
    'order': 5
}

class DNSTakeoverTool(BaseTool):
    """Tool for detecting potential DNS takeover vulnerabilities."""
    
    def __init__(self):
        super().__init__()
        self.name = 'dns_takeover'
        self.description = TOOL_CONFIG['description']
        self.findings = []
        self.vulnerable_patterns = {
            'aws_s3': [
                'NoSuchBucket',
                'The specified bucket does not exist'
            ],
            'github_pages': [
                'There isn\'t a GitHub Pages site here',
                'For root URLs (like http://example.com/) you must provide an index.html file'
            ],
            'azure': [
                'This Azure DNS zone is not configured correctly',
                'This webpage is not available'
            ],
            'cloudfront': [
                'The request could not be satisfied',
                'ERROR: The request could not be satisfied'
            ],
            'google_cloud': [
                'The requested URL was not found on this server',
                'Error 404 (Not Found)'
            ],
            'heroku': [
                'no-such-app.herokuapp.com',
                'herokucdn.com/error-pages/no-such-app.html'
            ]
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

    def check_cname_vulnerability(self, domain: str, cname: str) -> Optional[Dict[str, Any]]:
        """
        Check if a CNAME record indicates a potential takeover vulnerability.
        
        Args:
            domain: Domain being checked
            cname: CNAME record value
            
        Returns:
            Optional[Dict[str, Any]]: Vulnerability details if found
        """
        cname = cname.lower()
        
        # Check for each service's patterns
        for service, patterns in self.vulnerable_patterns.items():
            for pattern in patterns:
                if pattern.lower() in cname:
                    return {
                        'domain': domain,
                        'cname': cname,
                        'service': service,
                        'pattern': pattern,
                        'severity': 'High',
                        'description': f'Potential DNS takeover vulnerability found - {service}'
                    }
        
        return None

    def check_dangling_record(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Check for dangling DNS records that could lead to takeover.
        
        Args:
            domain: Domain to check
            
        Returns:
            Optional[Dict[str, Any]]: Vulnerability details if found
        """
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                try:
                    # Try to resolve the CNAME target
                    dns.resolver.resolve(cname, 'A')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return {
                        'domain': domain,
                        'cname': cname,
                        'severity': 'High',
                        'description': 'Dangling CNAME record detected - target does not resolve'
                    }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            logging.warning(f'Error checking {domain}: {str(e)}')
        
        return None

    def run(self, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run the DNS takeover vulnerability scan.
        
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
        
        for subdomain in subdomains:
            try:
                # Check for dangling records
                finding = self.check_dangling_record(subdomain)
                if finding:
                    self.findings.append(finding)
                    continue
                
                # Check CNAME records for known vulnerable patterns
                try:
                    answers = dns.resolver.resolve(subdomain, 'CNAME')
                    for rdata in answers:
                        cname = str(rdata.target).rstrip('.')
                        finding = self.check_cname_vulnerability(subdomain, cname)
                        if finding:
                            self.findings.append(finding)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                
            except Exception as e:
                logging.warning(f'Error scanning {subdomain}: {str(e)}')
        
        return self.findings

def main():
    """Main function for standalone usage."""
    tool = DNSTakeoverTool()
    args = {'domain': 'example.com'}
    findings = tool.run(args)
    for finding in findings:
        print(f"[{finding['severity']}] {finding['description']}")
        print(f"Domain: {finding['domain']}")
        print(f"CNAME: {finding['cname']}")
        print("---")

if __name__ == '__main__':
    main() 