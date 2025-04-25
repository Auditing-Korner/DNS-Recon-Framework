#!/usr/bin/env python3
"""
Cloud Service Enumeration Tool

Detects and analyzes cloud service usage:
- AWS resources and services
- Azure resources and endpoints
- GCP resources and projects
- Multi-cloud configurations
- Service dependencies
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import requests
import sys
import os
import json
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class CloudEnumerator(BaseTool):
    """Cloud Service Enumeration Tool"""
    
    def __init__(self):
        super().__init__(
            name="cloud_enum",
            description="Cloud Service Enumeration Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize cloud service signatures
        self.signatures = {
            'aws': {
                'domains': [
                    'amazonaws.com',
                    'cloudfront.net',
                    'awsglobalaccelerator.com'
                ],
                'services': {
                    's3': {
                        'patterns': [
                            's3.amazonaws.com',
                            's3-website'
                        ],
                        'http_check': True
                    },
                    'cloudfront': {
                        'patterns': [
                            'cloudfront.net'
                        ],
                        'http_check': True
                    },
                    'elasticbeanstalk': {
                        'patterns': [
                            'elasticbeanstalk.com'
                        ],
                        'http_check': True
                    }
                }
            },
            'azure': {
                'domains': [
                    'azure.com',
                    'azurewebsites.net',
                    'cloudapp.net'
                ],
                'services': {
                    'webapp': {
                        'patterns': [
                            'azurewebsites.net'
                        ],
                        'http_check': True
                    },
                    'storage': {
                        'patterns': [
                            'blob.core.windows.net',
                            'file.core.windows.net'
                        ],
                        'http_check': True
                    },
                    'cdn': {
                        'patterns': [
                            'azureedge.net'
                        ],
                        'http_check': True
                    }
                }
            },
            'gcp': {
                'domains': [
                    'googleapis.com',
                    'appspot.com',
                    'cloudfunctions.net'
                ],
                'services': {
                    'appengine': {
                        'patterns': [
                            'appspot.com'
                        ],
                        'http_check': True
                    },
                    'storage': {
                        'patterns': [
                            'storage.googleapis.com'
                        ],
                        'http_check': True
                    },
                    'functions': {
                        'patterns': [
                            'cloudfunctions.net'
                        ],
                        'http_check': True
                    }
                }
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run cloud service enumeration with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        providers = self.get_param('providers', 'all').split(',')
        check_http = self.get_param('check_http', True)
        max_threads = int(self.get_param('threads', 10))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Get subdomains first
            subdomains = self._enumerate_subdomains(domain, result)
            if not subdomains:
                result.add_warning("No subdomains found to check")
                return
            
            # Check each provider if specified
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                for provider, config in self.signatures.items():
                    if 'all' in providers or provider in providers:
                        # Submit tasks for each subdomain
                        for subdomain in subdomains:
                            futures.append(executor.submit(
                                self._check_cloud_usage,
                                subdomain,
                                provider,
                                config,
                                check_http,
                                result
                            ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in cloud check: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during cloud enumeration: {str(e)}")
            
    def _enumerate_subdomains(self, domain: str, result: ToolResult) -> Set[str]:
        """Enumerate subdomains using various methods"""
        subdomains = set()
        
        try:
            # Try zone transfer first
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    try:
                        xfr = dns.query.xfr(str(ns), domain)
                        zone = dns.zone.from_xfr(xfr)
                        for name, node in zone.nodes.items():
                            subdomain = str(name)
                            if subdomain != '@':
                                subdomains.add(f"{subdomain}.{domain}")
                    except:
                        continue
            except:
                pass
            
            # Try common record types
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if record_type == 'MX':
                            subdomains.add(str(rdata.exchange).rstrip('.'))
                        elif record_type == 'CNAME':
                            subdomains.add(str(rdata.target).rstrip('.'))
                        else:
                            subdomains.add(str(rdata))
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error enumerating subdomains: {str(e)}")
            
        return subdomains

    def _check_cloud_usage(self, subdomain: str, provider: str, config: Dict,
                          check_http: bool, result: ToolResult) -> None:
        """Check subdomain for cloud service usage"""
        try:
            # Check DNS records
            for record_type in ['CNAME', 'A']:
                try:
                    records = dns.resolver.resolve(subdomain, record_type)
                    for record in records:
                        target = str(record.target if record_type == 'CNAME' else record)
                        
                        # Check against provider domains
                        for domain in config['domains']:
                            if domain in target:
                                # Found cloud usage, check specific services
                                for service, service_config in config['services'].items():
                                    for pattern in service_config['patterns']:
                                        if pattern in target:
                                            finding = {
                                                'title': f"{provider.upper()} Service Detected",
                                                'description': f"Found {service} usage on {subdomain}",
                                                'risk_level': "Info",
                                                'details': {
                                                    'subdomain': subdomain,
                                                    'provider': provider,
                                                    'service': service,
                                                    'target': target,
                                                    'record_type': record_type
                                                }
                                            }
                                            
                                            # Add service-specific recommendations
                                            if service == 's3':
                                                finding['recommendations'] = [
                                                    'Verify bucket permissions',
                                                    'Enable bucket encryption',
                                                    'Configure access logging'
                                                ]
                                            elif service in ['cloudfront', 'cdn']:
                                                finding['recommendations'] = [
                                                    'Enable HTTPS only',
                                                    'Configure WAF rules',
                                                    'Review caching policies'
                                                ]
                                            elif 'storage' in service:
                                                finding['recommendations'] = [
                                                    'Review storage access policies',
                                                    'Enable encryption at rest',
                                                    'Configure monitoring'
                                                ]
                                            else:
                                                finding['recommendations'] = [
                                                    'Review service configuration',
                                                    'Enable logging and monitoring',
                                                    'Follow security best practices'
                                                ]
                                            
                                            result.add_finding(finding)
                                            
                                            # Check HTTP if enabled
                                            if check_http and service_config.get('http_check', False):
                                                self._check_http_endpoint(subdomain, result)
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error checking cloud usage for {subdomain}: {str(e)}")

    def _check_http_endpoint(self, subdomain: str, result: ToolResult) -> None:
        """Check HTTP endpoint for additional information"""
        try:
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(
                        f"{protocol}://{subdomain}",
                        timeout=self.resolver.timeout,
                        allow_redirects=False
                    )
                    
                    # Check response headers for cloud indicators
                    cloud_headers = {
                        'x-amz-': 'AWS',
                        'x-azure-': 'Azure',
                        'x-goog-': 'GCP'
                    }
                    
                    for header_prefix, provider in cloud_headers.items():
                        for header in response.headers:
                            if header.lower().startswith(header_prefix):
                                result.add_finding({
                                    'title': f"{provider} Headers Detected",
                                    'description': f"Found cloud service headers on {subdomain}",
                                    'risk_level': "Info",
                                    'details': {
                                        'subdomain': subdomain,
                                        'protocol': protocol,
                                        'provider': provider,
                                        'headers': {
                                            k: v for k, v in response.headers.items()
                                            if k.lower().startswith(header_prefix)
                                        }
                                    },
                                    'recommendations': [
                                        'Review exposed headers',
                                        'Configure security headers',
                                        'Minimize information disclosure'
                                    ]
                                })
                    break  # Stop after first successful connection
                except:
                    continue
                    
        except Exception as e:
            result.add_warning(f"Error checking HTTP endpoint for {subdomain}: {str(e)}")

def main():
    """Entry point for cloud enumerator"""
    tool = CloudEnumerator()
    return tool.main()

if __name__ == "__main__":
    main() 