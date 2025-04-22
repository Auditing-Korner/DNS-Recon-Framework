#!/usr/bin/env python3
"""
Cloud Takeover Detector

Detects potential cloud service takeover vulnerabilities:
- Dangling DNS records
- Unclaimed cloud resources
- Misconfigured cloud services
- Provider-specific checks
"""

import argparse
import json
import logging
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

try:
    from .framework_tool_template import FrameworkTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.framework_tool_template import FrameworkTool, ToolResult

# Check dependencies
MISSING_DEPS = []
try:
    import dns.resolver
except ImportError:
    MISSING_DEPS.append("dnspython")

try:
    import requests
except ImportError:
    MISSING_DEPS.append("requests")

try:
    import boto3
except ImportError:
    MISSING_DEPS.append("boto3")

try:
    from azure.mgmt.dns import DnsManagementClient
except ImportError:
    MISSING_DEPS.append("azure-mgmt-dns")

try:
    from google.cloud import dns
except ImportError:
    MISSING_DEPS.append("google-cloud-dns")

@dataclass
class CloudTakeoverResult:
    """Container for cloud takeover scan results"""
    domain: str
    provider: Optional[str]
    is_vulnerable: bool
    evidence: List[str]
    risk_level: str
    details: Dict
    errors: List[str]

class CloudTakeoverDetector(FrameworkTool):
    """Cloud Service Takeover Detection Tool"""
    
    def __init__(self):
        super().__init__(
            name="cloud-takeover-detector",
            description="Cloud Service Takeover Detection Tool"
        )
        
        # Cloud providers to check
        self.providers = {
            "aws": {
                "services": ["s3", "cloudfront", "elasticbeanstalk", "route53"],
                "patterns": {
                    "s3": r"\.s3\.amazonaws\.com$",
                    "cloudfront": r"\.cloudfront\.net$",
                    "elasticbeanstalk": r"\.elasticbeanstalk\.com$"
                }
            },
            "azure": {
                "services": ["blob", "webapp", "trafficmanager"],
                "patterns": {
                    "blob": r"\.blob\.core\.windows\.net$",
                    "webapp": r"\.azurewebsites\.net$",
                    "trafficmanager": r"\.trafficmanager\.net$"
                }
            },
            "gcp": {
                "services": ["storage", "appengine", "compute"],
                "patterns": {
                    "storage": r"\.storage\.googleapis\.com$",
                    "appengine": r"\.appspot\.com$",
                    "compute": r"\.googleapis\.com$"
                }
            }
        }
        
        # Common response patterns indicating takeover possibility
        self.takeover_indicators = {
            "NoSuchBucket": "AWS S3 bucket not claimed",
            "NoSuchWebApp": "Azure Web App available",
            "NoSuchInstance": "GCP instance not claimed",
            "404 Not Found": "Resource not found",
            "403 Forbidden": "Access denied but resource exists",
            "DNS resolution failed": "DNS record exists but no service"
        }
    
    def setup_tool_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Set up tool-specific arguments"""
        parser.add_argument('domain', help='Domain to analyze')
        parser.add_argument('--provider', choices=['aws', 'azure', 'gcp', 'all'],
                          default='all', help='Cloud provider to check')
        parser.add_argument('--timeout', type=int, default=10,
                          help='Connection timeout in seconds')
        parser.add_argument('--threads', type=int, default=5,
                          help='Number of concurrent threads')
        parser.add_argument('--check-dns', action='store_true',
                          help='Check DNS misconfigurations')
        parser.add_argument('--check-http', action='store_true',
                          help='Check HTTP responses')
        parser.add_argument('--check-all', action='store_true',
                          help='Run all checks')
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        """Execute cloud takeover detection"""
        try:
            # Check dependencies
            if MISSING_DEPS:
                result.add_error(f"Missing required dependencies: {', '.join(MISSING_DEPS)}")
                return
            
            # Update metadata
            result.metadata.update({
                "domain": args.domain,
                "timestamp": datetime.now().isoformat(),
                "provider": args.provider,
                "checks": {
                    "dns": args.check_all or args.check_dns,
                    "http": args.check_all or args.check_http
                }
            })
            
            # Analyze domain
            scan_result = self.analyze_domain(args.domain, args)
            
            # Add findings based on analysis
            if scan_result.is_vulnerable:
                result.add_finding(
                    title=f"Potential Cloud Takeover: {scan_result.domain}",
                    description=f"Domain appears vulnerable to cloud service takeover" + 
                              (f" on {scan_result.provider}" if scan_result.provider else ""),
                    risk_level=scan_result.risk_level,
                    evidence="\n".join(scan_result.evidence)
                )
            
            # Add provider-specific findings
            if scan_result.details.get("provider_findings"):
                for finding in scan_result.details["provider_findings"]:
                    result.add_finding(
                        title=finding["title"],
                        description=finding["description"],
                        risk_level=finding["risk_level"],
                        evidence=finding.get("evidence", "No specific evidence")
                    )
            
            # Add any errors
            for error in scan_result.errors:
                result.add_error(error)
            
        except Exception as e:
            result.add_error(f"Error during cloud takeover detection: {str(e)}")
    
    def analyze_domain(self, domain: str, args: argparse.Namespace) -> CloudTakeoverResult:
        """Analyze a domain for cloud service takeover vulnerabilities"""
        evidence = []
        errors = []
        details = {}
        provider = None
        is_vulnerable = False
        risk_level = "Info"
        
        try:
            # Check DNS records
            if args.check_all or args.check_dns:
                dns_results = self._check_dns_records(domain)
                if dns_results.get("evidence"):
                    evidence.extend(dns_results["evidence"])
                if dns_results.get("errors"):
                    errors.extend(dns_results["errors"])
                if dns_results.get("provider"):
                    provider = dns_results["provider"]
                details["dns_results"] = dns_results
            
            # Check HTTP responses
            if args.check_all or args.check_http:
                http_results = self._check_http_endpoints(domain)
                if http_results.get("evidence"):
                    evidence.extend(http_results["evidence"])
                if http_results.get("errors"):
                    errors.extend(http_results["errors"])
                details["http_results"] = http_results
            
            # Check specific provider if specified
            if args.provider != 'all':
                provider_results = self._check_provider(domain, args.provider)
                if provider_results.get("evidence"):
                    evidence.extend(provider_results["evidence"])
                if provider_results.get("errors"):
                    errors.extend(provider_results["errors"])
                details["provider_results"] = provider_results
            
            # Determine if vulnerable based on evidence
            is_vulnerable = bool(evidence)
            risk_level = "High" if is_vulnerable else "Info"
            
            return CloudTakeoverResult(
                domain=domain,
                provider=provider,
                is_vulnerable=is_vulnerable,
                evidence=evidence,
                risk_level=risk_level,
                details=details,
                errors=errors
            )
            
        except Exception as e:
            return CloudTakeoverResult(
                domain=domain,
                provider=None,
                is_vulnerable=False,
                evidence=[],
                risk_level="Error",
                details={},
                errors=[f"Error during analysis: {str(e)}"]
            )
    
    def _check_dns_records(self, domain: str) -> Dict:
        """Check DNS records for takeover indicators"""
        results = {
            "evidence": [],
            "errors": [],
            "provider": None,
            "records": {}
        }
        
        try:
            resolver = dns.resolver.Resolver()
            
            # Check A records
            try:
                answers = resolver.resolve(domain, 'A')
                results["records"]["A"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                results["evidence"].append(f"Domain {domain} does not exist but may be claimable")
            except Exception as e:
                results["errors"].append(f"Error checking A records: {str(e)}")
            
            # Check CNAME records
            try:
                answers = resolver.resolve(domain, 'CNAME')
                cnames = [str(rdata.target) for rdata in answers]
                results["records"]["CNAME"] = cnames
                
                # Check for cloud service patterns
                for provider, info in self.providers.items():
                    for service, pattern in info["patterns"].items():
                        import re
                        for cname in cnames:
                            if re.search(pattern, cname):
                                results["provider"] = provider
                                results["evidence"].append(
                                    f"CNAME points to {provider} {service} service: {cname}"
                                )
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                results["errors"].append(f"Error checking CNAME records: {str(e)}")
            
            return results
            
        except Exception as e:
            results["errors"].append(f"Error during DNS checks: {str(e)}")
            return results
    
    def _check_http_endpoints(self, domain: str) -> Dict:
        """Check HTTP endpoints for takeover indicators"""
        results = {
            "evidence": [],
            "errors": [],
            "responses": {}
        }
        
        try:
            # Check both HTTP and HTTPS
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}"
                try:
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    results["responses"][protocol] = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "content_length": len(response.content)
                    }
                    
                    # Check for takeover indicators in response
                    for indicator, description in self.takeover_indicators.items():
                        if indicator in response.text:
                            results["evidence"].append(
                                f"{protocol.upper()} endpoint indicates possible takeover: {description}"
                            )
                except requests.exceptions.RequestException as e:
                    results["errors"].append(f"Error checking {url}: {str(e)}")
        
        except Exception as e:
            results["errors"].append(f"Error during HTTP checks: {str(e)}")
        
        return results
    
    def _check_provider(self, domain: str, provider: str) -> Dict:
        """Check specific cloud provider for takeover possibilities"""
        results = {
            "evidence": [],
            "errors": [],
            "findings": []
        }
        
        try:
            if provider == "aws":
                self._check_aws(domain, results)
            elif provider == "azure":
                self._check_azure(domain, results)
            elif provider == "gcp":
                self._check_gcp(domain, results)
        except Exception as e:
            results["errors"].append(f"Error checking {provider}: {str(e)}")
        
        return results
    
    def _check_aws(self, domain: str, results: Dict) -> None:
        """Check AWS-specific takeover possibilities"""
        try:
            # Initialize AWS session
            session = boto3.Session()
            
            # Check S3
            s3_client = session.client('s3')
            if '.s3.' in domain:
                bucket_name = domain.split('.s3.')[0]
                try:
                    s3_client.head_bucket(Bucket=bucket_name)
                except s3_client.exceptions.ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code == '404':
                        results["evidence"].append(f"S3 bucket '{bucket_name}' exists but is not claimed")
                    elif error_code == '403':
                        results["evidence"].append(f"S3 bucket '{bucket_name}' exists and is claimed")
            
            # Check CloudFront
            cloudfront_client = session.client('cloudfront')
            if '.cloudfront.net' in domain:
                distribution_id = domain.split('.cloudfront.net')[0]
                try:
                    cloudfront_client.get_distribution(Id=distribution_id)
                except cloudfront_client.exceptions.NoSuchDistribution:
                    results["evidence"].append(f"CloudFront distribution '{distribution_id}' is available")
            
        except Exception as e:
            results["errors"].append(f"AWS check error: {str(e)}")
    
    def _check_azure(self, domain: str, results: Dict) -> None:
        """Check Azure-specific takeover possibilities"""
        try:
            # Check Azure Storage
            if '.blob.core.windows.net' in domain:
                storage_account = domain.split('.blob.core.windows.net')[0]
                url = f"https://{storage_account}.blob.core.windows.net"
                response = requests.head(url, timeout=10)
                if response.status_code == 404:
                    results["evidence"].append(f"Azure Storage account '{storage_account}' may be available")
            
            # Check Azure Web Apps
            if '.azurewebsites.net' in domain:
                webapp_name = domain.split('.azurewebsites.net')[0]
                url = f"https://{webapp_name}.azurewebsites.net"
                response = requests.head(url, timeout=10)
                if response.status_code == 404:
                    results["evidence"].append(f"Azure Web App '{webapp_name}' may be available")
            
        except Exception as e:
            results["errors"].append(f"Azure check error: {str(e)}")
    
    def _check_gcp(self, domain: str, results: Dict) -> None:
        """Check GCP-specific takeover possibilities"""
        try:
            # Check Google Cloud Storage
            if '.storage.googleapis.com' in domain:
                bucket_name = domain.split('.storage.googleapis.com')[0]
                url = f"https://storage.googleapis.com/{bucket_name}"
                response = requests.head(url, timeout=10)
                if response.status_code == 404:
                    results["evidence"].append(f"GCP Storage bucket '{bucket_name}' may be available")
            
            # Check App Engine
            if '.appspot.com' in domain:
                app_name = domain.split('.appspot.com')[0]
                url = f"https://{app_name}.appspot.com"
                response = requests.head(url, timeout=10)
                if response.status_code == 404:
                    results["evidence"].append(f"App Engine app '{app_name}' may be available")
            
        except Exception as e:
            results["errors"].append(f"GCP check error: {str(e)}")

def main():
    """Main entry point"""
    tool = CloudTakeoverDetector()
    tool.run()

if __name__ == "__main__":
    main() 