#!/usr/bin/env python3

import dns.resolver
import dns.exception
import requests
from typing import Dict, List, Optional, Any
from pathlib import Path
import sys
import os
import json

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class CloudTakeoverDetector(BaseTool):
    """Cloud Service Takeover Detection Tool"""
    
    def __init__(self):
        super().__init__(
            name="takeover",
            description="Cloud Service Takeover Detection Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run cloud takeover detection with provided arguments"""
        domain = self.get_param('domain')
        provider = self.get_param('provider', 'all')
        timeout = self.get_param('timeout', 5)
        check_dns = self.get_param('check_dns', True)
        check_http = self.get_param('check_http', True)
        threads = self.get_param('threads', 10)
        verify_ssl = self.get_param('verify_ssl', False)
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        try:
            # Load provider patterns
            patterns = self._load_patterns()
            if not patterns:
                result.add_error("Could not load provider patterns")
                return
                
            # Check each provider
            for provider_name, provider_info in patterns.items():
                if provider != 'all' and provider_name != provider:
                    continue
                    
                if check_dns:
                    self._check_provider_dns(domain, provider_name, provider_info, result)
                    
                if check_http:
                    self._check_provider_http(domain, provider_name, provider_info, verify_ssl, result)
                
        except Exception as e:
            result.add_error(f"Error during takeover detection: {str(e)}")
            
    def _load_patterns(self) -> Dict:
        """Load provider patterns from file"""
        try:
            pattern_file = Path(__file__).parent / 'data' / 'cloud_patterns.json'
            if not pattern_file.exists():
                return {}
                
            with open(pattern_file) as f:
                return json.load(f)
        except Exception:
            return {}
            
    def _check_provider_dns(self, domain: str, provider: str, provider_info: Dict, result: ToolResult) -> None:
        """Check domain against a provider's DNS patterns"""
        try:
            # Check DNS patterns
            for pattern in provider_info.get('dns_patterns', []):
                test_domain = pattern.format(domain=domain)
                try:
                    cname_records = self.resolver.resolve(test_domain, 'CNAME')
                    for rr in cname_records:
                        cname = str(rr.target).rstrip('.')
                        if any(p.lower() in cname.lower() for p in provider_info.get('cname_patterns', [])):
                            result.add_finding({
                                'title': 'Cloud Service Found',
                                'description': f'Domain {test_domain} uses {provider} services',
                                'risk_level': 'Info',
                                'details': {
                                    'domain': test_domain,
                                    'provider': provider,
                                    'cname': cname,
                                    'type': 'DNS'
                                }
                            })
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error checking DNS for provider {provider}: {str(e)}")
            
    def _check_provider_http(self, domain: str, provider: str, provider_info: Dict, verify_ssl: bool, result: ToolResult) -> None:
        """Check domain for provider's HTTP takeover signatures"""
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=self.resolver.timeout,
                verify=verify_ssl
            )
            
            # Check response against takeover signatures
            for signature in provider_info.get('takeover_signatures', []):
                if signature.lower() in response.text.lower():
                    result.add_finding({
                        'title': 'Potential Cloud Service Takeover',
                        'description': f'Domain {domain} appears vulnerable to takeover via {provider}',
                        'risk_level': 'High',
                        'details': {
                            'domain': domain,
                            'provider': provider,
                            'signature': signature,
                            'type': 'HTTP'
                        },
                        'recommendations': [
                            'Verify cloud service configuration',
                            'Remove DNS records if service is not in use',
                            'Configure service properly if still needed'
                        ]
                    })
                    break
                    
        except Exception as e:
            result.add_warning(f"Error checking HTTP for {domain}: {str(e)}")

def main():
    """Entry point for cloud takeover detector"""
    tool = CloudTakeoverDetector()
    return tool.main()

if __name__ == "__main__":
    main() 