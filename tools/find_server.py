#!/usr/bin/env python3
"""
Server Discovery Tool

Identifies and analyzes server infrastructure:
- DNS server discovery
- Web server detection
- Mail server enumeration
- Load balancer detection
- CDN identification
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import socket
import requests
import sys
import os
import json
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

# Import base tool directly
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    # Fallback for direct script execution
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class ServerFinder(BaseTool):
    """Tool for discovering and analyzing server infrastructure"""
    
    def __init__(self):
        super().__init__(
            name="find_server",
            description="Server Discovery Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0
        self.findings = []
        
        # Initialize server signatures
        self.signatures = {
            'web_servers': {
                'apache': {
                    'headers': ['server', 'x-powered-by'],
                    'patterns': ['apache', 'httpd'],
                    'ports': [80, 443, 8080, 8443]
                },
                'nginx': {
                    'headers': ['server', 'x-powered-by'],
                    'patterns': ['nginx'],
                    'ports': [80, 443, 8080]
                },
                'iis': {
                    'headers': ['server', 'x-powered-by'],
                    'patterns': ['iis', 'asp.net'],
                    'ports': [80, 443, 8172]
                }
            },
            'mail_servers': {
                'exchange': {
                    'patterns': ['exchange', 'outlook'],
                    'ports': [25, 587, 993]
                },
                'postfix': {
                    'patterns': ['postfix'],
                    'ports': [25, 587, 465]
                },
                'sendmail': {
                    'patterns': ['sendmail'],
                    'ports': [25, 587]
                }
            },
            'load_balancers': {
                'haproxy': {
                    'headers': ['x-haproxy', 'x-varnish'],
                    'patterns': ['haproxy']
                },
                'f5': {
                    'headers': ['x-f5', 'x-bigip'],
                    'patterns': ['f5', 'bigip']
                },
                'nginx_lb': {
                    'headers': ['x-nginx-lb'],
                    'patterns': ['nginx']
                }
            },
            'cdns': {
                'cloudflare': {
                    'headers': ['cf-ray', 'cf-cache-status'],
                    'patterns': ['cloudflare']
                },
                'akamai': {
                    'headers': ['x-akamai-transformed'],
                    'patterns': ['akamai', 'akam']
                },
                'fastly': {
                    'headers': ['x-served-by', 'x-cache'],
                    'patterns': ['fastly']
                }
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run the server finder tool with the given arguments"""
        # Initialize result if not provided
        if result is None:
            result = self.get_result()
        
        # Get domain parameter
        domain = self.get_param("domain")
        if not domain:
            result.success = False
            result.add_error("Domain not specified")
            return

        # Update resolver settings
        timeout = self.get_param("timeout", 2.0)
        self.resolver.timeout = float(timeout)
        self.resolver.lifetime = float(timeout)
        
        nameserver = self.get_param("nameserver")
        if nameserver:
            self.resolver.nameservers = [nameserver]

        try:
            # DNS Server Discovery
            dns_servers = self._find_dns_servers(domain)
            for finding in dns_servers:
                result.add_finding(finding)

            # Web Server Detection if enabled
            if self.get_param("check_web", True):
                web_servers = self._find_web_servers(domain)
                for finding in web_servers:
                    result.add_finding(finding)

            # Mail Server Detection if enabled
            if self.get_param("check_mail", True):
                mail_servers = self._find_mail_servers(domain)
                for finding in mail_servers:
                    result.add_finding(finding)

            # Load Balancer Detection if enabled
            if self.get_param("check_lb", True):
                lb_findings = self._detect_load_balancers(domain)
                for finding in lb_findings:
                    result.add_finding(finding)

            # CDN Detection if enabled
            if self.get_param("check_cdn", True):
                cdn_findings = self._detect_cdn(domain)
                for finding in cdn_findings:
                    result.add_finding(finding)

            # Set success if we got this far
            result.success = True

        except Exception as e:
            result.success = False
            result.add_error(f"Error during server discovery: {str(e)}")

    def _find_dns_servers(self, domain: str) -> List[Dict[str, Any]]:
        """Find DNS servers for the domain"""
        findings = []
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_name)
                    findings.append({
                        'type': 'dns_server',
                        'server': ns_name,
                        'ip': ns_ip,
                        'description': f'DNS server {ns_name} ({ns_ip}) found for {domain}',
                        'severity': 'info',
                        'recommendation': 'Verify DNS server configuration is secure'
                    })
                except socket.gaierror:
                    findings.append({
                        'type': 'dns_server',
                        'server': ns_name,
                        'ip': None,
                        'description': f'DNS server {ns_name} found but IP resolution failed',
                        'severity': 'warning',
                        'recommendation': 'Check DNS server availability and configuration'
                    })
        except dns.exception.DNSException as e:
            findings.append({
                'type': 'dns_server',
                'server': None,
                'ip': None,
                'description': f'Failed to retrieve NS records for {domain}: {str(e)}',
                'severity': 'error',
                'recommendation': 'Verify domain name and DNS configuration'
            })
        return findings

    def _find_web_servers(self, domain: str) -> List[Dict[str, Any]]:
        """Find web servers for the domain"""
        findings = []
        try:
            for server_type, config in self.signatures['web_servers'].items():
                for port in config['ports']:
                    try:
                        # Try HTTPS first, then HTTP
                        for protocol in ['https', 'http']:
                            try:
                                response = requests.get(
                                    f"{protocol}://{domain}:{port}",
                                    timeout=self.resolver.timeout,
                                    verify=False
                                )
                                
                                # Check headers
                                for header in config['headers']:
                                    if header in response.headers:
                                        header_value = response.headers[header].lower()
                                        for pattern in config['patterns']:
                                            if pattern in header_value:
                                                findings.append({
                                                    'type': f"{server_type.upper()} Web Server",
                                                    'description': f"Found {server_type} web server",
                                                    'risk_level': "Info",
                                                    'details': {
                                                        'domain': domain,
                                                        'server_type': server_type,
                                                        'protocol': protocol,
                                                        'port': port,
                                                        'header': header,
                                                        'value': response.headers[header]
                                                    },
                                                    'recommendations': [
                                                        'Verify server configuration',
                                                        'Review security settings',
                                                        'Check version information'
                                                    ]
                                                })
                                break  # Stop after first successful connection
                            except:
                                continue
                    except:
                        continue
        except Exception as e:
            findings.append({
                'type': 'web_server',
                'description': f"Error checking web server for {domain}: {str(e)}",
                'risk_level': 'warning',
                'severity': 'warning',
                'recommendation': 'Verify server availability and configuration'
            })
        return findings

    def _find_mail_servers(self, domain: str) -> List[Dict[str, Any]]:
        """Find mail servers for the domain"""
        findings = []
        try:
            # Check MX records first
            try:
                mx_records = self.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    mx_host = str(mx.exchange).rstrip('.')
                    
                    # Check each mail server type
                    for server_type, config in self.signatures['mail_servers'].items():
                        for port in config['ports']:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(self.resolver.timeout)
                                sock.connect((mx_host, port))
                                
                                # Get banner
                                banner = sock.recv(1024).decode().lower()
                                sock.close()
                                
                                for pattern in config['patterns']:
                                    if pattern in banner:
                                        findings.append({
                                            'type': f"{server_type.upper()} Mail Server",
                                            'description': f"Found {server_type} mail server",
                                            'risk_level': "Info",
                                            'details': {
                                                'domain': domain,
                                                'server_type': server_type,
                                                'mx_host': mx_host,
                                                'port': port,
                                                'banner': banner
                                            },
                                            'recommendations': [
                                                'Verify mail server configuration',
                                                'Review mail security settings',
                                                'Check for open relay'
                                            ]
                                        })
                            except:
                                continue
            except:
                pass
        except Exception as e:
            findings.append({
                'type': 'mail_server',
                'description': f"Error checking mail server for {domain}: {str(e)}",
                'risk_level': 'warning',
                'severity': 'warning',
                'recommendation': 'Verify mail server availability and configuration'
            })
        return findings

    def _detect_load_balancers(self, domain: str) -> List[Dict[str, Any]]:
        """Detect load balancers for the domain"""
        findings = []
        try:
            for lb_type, config in self.signatures['load_balancers'].items():
                try:
                    # Try HTTPS first, then HTTP
                    for protocol in ['https', 'http']:
                        try:
                            response = requests.get(
                                f"{protocol}://{domain}",
                                timeout=self.resolver.timeout,
                                verify=False
                            )
                            
                            # Check headers
                            for header in config['headers']:
                                if header in response.headers:
                                    header_value = response.headers[header].lower()
                                    for pattern in config['patterns']:
                                        if pattern in header_value:
                                            findings.append({
                                                'type': f"{lb_type.upper()} Load Balancer",
                                                'description': f"Found {lb_type} load balancer",
                                                'risk_level': "Info",
                                                'details': {
                                                    'domain': domain,
                                                    'lb_type': lb_type,
                                                    'protocol': protocol,
                                                    'header': header,
                                                    'value': response.headers[header]
                                                },
                                                'recommendations': [
                                                    'Verify load balancer configuration',
                                                    'Review SSL termination',
                                                    'Check health checks'
                                                ]
                                            })
                            break  # Stop after first successful connection
                        except:
                            continue
                except:
                    continue
        except Exception as e:
            findings.append({
                'type': 'load_balancer',
                'description': f"Error checking load balancer for {domain}: {str(e)}",
                'risk_level': 'warning',
                'severity': 'warning',
                'recommendation': 'Verify load balancer availability and configuration'
            })
        return findings

    def _detect_cdn(self, domain: str) -> List[Dict[str, Any]]:
        """Detect CDN for the domain"""
        findings = []
        try:
            for cdn_type, config in self.signatures['cdns'].items():
                try:
                    # Try HTTPS first, then HTTP
                    for protocol in ['https', 'http']:
                        try:
                            response = requests.get(
                                f"{protocol}://{domain}",
                                timeout=self.resolver.timeout,
                                verify=False
                            )
                            
                            # Check headers
                            for header in config['headers']:
                                if header in response.headers:
                                    header_value = response.headers[header].lower()
                                    for pattern in config['patterns']:
                                        if pattern in header_value:
                                            findings.append({
                                                'type': f"{cdn_type.upper()} CDN",
                                                'description': f"Found {cdn_type} CDN",
                                                'risk_level': "Info",
                                                'details': {
                                                    'domain': domain,
                                                    'cdn_type': cdn_type,
                                                    'protocol': protocol,
                                                    'header': header,
                                                    'value': response.headers[header]
                                                },
                                                'recommendations': [
                                                    'Verify CDN configuration',
                                                    'Review caching settings',
                                                    'Check SSL configuration'
                                                ]
                                            })
                            break  # Stop after first successful connection
                        except:
                            continue
                except:
                    continue
        except Exception as e:
            findings.append({
                'type': 'cdn',
                'description': f"Error checking CDN for {domain}: {str(e)}",
                'risk_level': 'warning',
                'severity': 'warning',
                'recommendation': 'Verify CDN availability and configuration'
            })
        return findings

def main():
    """Main entry point for the tool"""
    tool = ServerFinder()
    
    if len(sys.argv) > 1:
        # Running as standalone script
        parser = argparse.ArgumentParser(description=tool.description)
        parser.add_argument('--domain', required=True, help='Target domain')
        parser.add_argument('--output', help='Output file path')
        parser.add_argument('--timeout', type=float, default=2.0, help='Query timeout')
        parser.add_argument('--nameserver', help='Custom nameserver to use')
        parser.add_argument('--check-web', action='store_true', help='Check web servers')
        parser.add_argument('--check-mail', action='store_true', help='Check mail servers')
        parser.add_argument('--check-lb', action='store_true', help='Check load balancers')
        parser.add_argument('--check-cdn', action='store_true', help='Check CDN usage')
        args = parser.parse_args()
        
        # Convert args to dict
        params = vars(args)
    else:
        # Running as module
        params = {}
    
    # Run the tool
    result = tool.run(params)
    
    # Handle output
    if params.get('output'):
        output_file = params['output']
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=4)
    else:
        print(json.dumps(result, indent=4))
    
    return result

if __name__ == '__main__':
    main() 