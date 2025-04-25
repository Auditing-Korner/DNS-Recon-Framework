#!/usr/bin/env python3
"""
SSL/TLS Security Scanner Tool

Analyzes SSL/TLS configuration and security:
- Certificate validation
- Protocol support
- Cipher suites
- Known vulnerabilities
- Security headers
- Best practices compliance
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import socket
import ssl
import sys
import os
import json
import requests
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class SSLScanner(BaseTool):
    """SSL/TLS Security Scanner Tool"""
    
    def __init__(self):
        super().__init__(
            name="ssl_scanner",
            description="SSL/TLS Security Scanner Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize security checks
        self.checks = {
            'protocols': {
                'SSLv2': {'port': 443, 'secure': False},
                'SSLv3': {'port': 443, 'secure': False},
                'TLSv1.0': {'port': 443, 'secure': False},
                'TLSv1.1': {'port': 443, 'secure': False},
                'TLSv1.2': {'port': 443, 'secure': True},
                'TLSv1.3': {'port': 443, 'secure': True}
            },
            'ciphers': {
                'weak': [
                    'RC4',
                    'DES',
                    '3DES',
                    'MD5',
                    'NULL',
                    'EXPORT',
                    'ADH'
                ],
                'recommended': [
                    'ECDHE',
                    'AES256',
                    'GCM',
                    'SHA384'
                ]
            },
            'cert_issues': {
                'weak_key': 2048,  # Minimum key size in bits
                'max_age': 398,    # Maximum cert age in days
                'sha1_sig': False  # SHA1 signatures allowed
            },
            'headers': {
                'required': {
                    'Strict-Transport-Security': None,
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': None,
                    'X-XSS-Protection': '1; mode=block'
                },
                'recommended': {
                    'Content-Security-Policy': None,
                    'Referrer-Policy': None,
                    'Feature-Policy': None
                }
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run SSL/TLS security scanning with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_subdomains = self.get_param('check_subdomains', True)
        max_threads = int(self.get_param('threads', 10))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Get domains to check
            domains = set([domain])
            if check_subdomains:
                subdomains = self._enumerate_subdomains(domain, result)
                domains.update(subdomains)
            
            # Check each domain
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                for target in domains:
                    futures.append(executor.submit(
                        self._check_ssl,
                        target,
                        result
                    ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in SSL check: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during SSL scanning: {str(e)}")
            
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

    def _check_ssl(self, domain: str, result: ToolResult) -> None:
        """Check SSL/TLS configuration for a domain"""
        try:
            # Check protocols and ciphers
            supported_protocols = {}
            for protocol, config in self.checks['protocols'].items():
                try:
                    context = ssl.SSLContext()
                    if protocol == 'SSLv2':
                        context.protocol = ssl.PROTOCOL_SSLv2
                    elif protocol == 'SSLv3':
                        context.protocol = ssl.PROTOCOL_SSLv3
                    elif protocol == 'TLSv1.0':
                        context.protocol = ssl.PROTOCOL_TLSv1
                    elif protocol == 'TLSv1.1':
                        context.protocol = ssl.PROTOCOL_TLSv1_1
                    elif protocol == 'TLSv1.2':
                        context.protocol = ssl.PROTOCOL_TLSv1_2
                    elif protocol == 'TLSv1.3':
                        context.protocol = ssl.PROTOCOL_TLS
                        context.minimum_version = ssl.TLSVersion.TLSv1_3
                    
                    with socket.create_connection((domain, config['port']), timeout=self.resolver.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            supported_protocols[protocol] = {
                                'cipher': ssock.cipher(),
                                'version': ssock.version()
                            }
                            
                            # Check for insecure protocols
                            if not config['secure']:
                                result.add_finding({
                                    'title': f"Insecure Protocol {protocol}",
                                    'description': f"Server supports insecure protocol {protocol}",
                                    'risk_level': "High",
                                    'details': {
                                        'domain': domain,
                                        'protocol': protocol,
                                        'cipher_suite': ssock.cipher()
                                    },
                                    'recommendations': [
                                        'Disable insecure protocol',
                                        'Configure minimum TLS version',
                                        'Review SSL/TLS configuration'
                                    ]
                                })
                except:
                    continue
            
            # Get certificate information
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=self.resolver.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_data = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(cert_data, default_backend())
                        
                        # Check certificate issues
                        self._check_certificate(domain, cert, result)
                        
                        # Check cipher suites
                        cipher = ssock.cipher()
                        self._check_cipher_suite(domain, cipher, result)
            except:
                pass
            
            # Check security headers
            try:
                response = requests.get(
                    f"https://{domain}",
                    timeout=self.resolver.timeout,
                    verify=True
                )
                
                self._check_security_headers(domain, response.headers, result)
            except:
                pass
                
        except Exception as e:
            result.add_warning(f"Error checking SSL for {domain}: {str(e)}")

    def _check_certificate(self, domain: str, cert: x509.Certificate, result: ToolResult) -> None:
        """Check certificate for security issues"""
        try:
            # Check key size
            public_key = cert.public_key()
            key_size = public_key.key_size
            if key_size < self.checks['cert_issues']['weak_key']:
                result.add_finding({
                    'title': "Weak Certificate Key",
                    'description': f"Certificate uses {key_size}-bit key (minimum recommended: {self.checks['cert_issues']['weak_key']})",
                    'risk_level': "High",
                    'details': {
                        'domain': domain,
                        'key_size': key_size,
                        'recommended_size': self.checks['cert_issues']['weak_key']
                    },
                    'recommendations': [
                        'Generate new certificate with stronger key',
                        'Use minimum 2048-bit RSA or equivalent',
                        'Review certificate security'
                    ]
                })
            
            # Check certificate age
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            age_days = (not_after - not_before).days
            
            if age_days > self.checks['cert_issues']['max_age']:
                result.add_finding({
                    'title': "Long-lived Certificate",
                    'description': f"Certificate validity period ({age_days} days) exceeds recommended maximum",
                    'risk_level': "Medium",
                    'details': {
                        'domain': domain,
                        'validity_days': age_days,
                        'not_before': str(not_before),
                        'not_after': str(not_after),
                        'recommended_max': self.checks['cert_issues']['max_age']
                    },
                    'recommendations': [
                        'Use shorter certificate validity period',
                        'Implement automated certificate renewal',
                        'Follow industry best practices'
                    ]
                })
            
            # Check signature algorithm
            sig_algorithm = cert.signature_algorithm_oid
            if 'sha1' in sig_algorithm.dotted_string.lower():
                result.add_finding({
                    'title': "Weak Certificate Signature",
                    'description': "Certificate uses SHA1 signature algorithm",
                    'risk_level': "High",
                    'details': {
                        'domain': domain,
                        'signature_algorithm': sig_algorithm.dotted_string
                    },
                    'recommendations': [
                        'Generate new certificate with SHA256 or stronger',
                        'Update certificate signing policy',
                        'Review signature algorithms'
                    ]
                })
                
        except Exception as e:
            result.add_warning(f"Error checking certificate for {domain}: {str(e)}")

    def _check_cipher_suite(self, domain: str, cipher: tuple, result: ToolResult) -> None:
        """Check cipher suite for security issues"""
        try:
            cipher_name = cipher[0]
            
            # Check for weak ciphers
            for weak_cipher in self.checks['ciphers']['weak']:
                if weak_cipher in cipher_name:
                    result.add_finding({
                        'title': "Weak Cipher Suite",
                        'description': f"Server supports weak cipher suite containing {weak_cipher}",
                        'risk_level': "High",
                        'details': {
                            'domain': domain,
                            'cipher_suite': cipher_name,
                            'weak_component': weak_cipher
                        },
                        'recommendations': [
                            'Disable weak cipher suites',
                            'Configure secure cipher order',
                            'Review cipher suite configuration'
                        ]
                    })
            
            # Check for recommended ciphers
            recommended_found = False
            for rec_cipher in self.checks['ciphers']['recommended']:
                if rec_cipher in cipher_name:
                    recommended_found = True
                    break
            
            if not recommended_found:
                result.add_finding({
                    'title': "Non-recommended Cipher Suite",
                    'description': "Server does not prefer recommended cipher suites",
                    'risk_level': "Medium",
                    'details': {
                        'domain': domain,
                        'cipher_suite': cipher_name,
                        'recommended_ciphers': self.checks['ciphers']['recommended']
                    },
                    'recommendations': [
                        'Configure recommended cipher suites',
                        'Prioritize secure ciphers',
                        'Follow cipher suite best practices'
                    ]
                })
                
        except Exception as e:
            result.add_warning(f"Error checking cipher suite for {domain}: {str(e)}")

    def _check_security_headers(self, domain: str, headers: Dict, result: ToolResult) -> None:
        """Check for required and recommended security headers"""
        try:
            # Check required headers
            for header, value in self.checks['headers']['required'].items():
                if header not in headers:
                    result.add_finding({
                        'title': f"Missing {header} Header",
                        'description': f"Required security header {header} not found",
                        'risk_level': "High",
                        'details': {
                            'domain': domain,
                            'header': header,
                            'expected_value': value if value else 'any'
                        },
                        'recommendations': [
                            f"Add {header} header",
                            'Configure secure header value',
                            'Review security headers'
                        ]
                    })
                elif value and headers[header] != value:
                    result.add_finding({
                        'title': f"Incorrect {header} Value",
                        'description': f"Security header {header} has incorrect value",
                        'risk_level': "Medium",
                        'details': {
                            'domain': domain,
                            'header': header,
                            'current_value': headers[header],
                            'expected_value': value
                        },
                        'recommendations': [
                            f"Update {header} header value",
                            'Follow header configuration guidelines',
                            'Review security header policy'
                        ]
                    })
            
            # Check recommended headers
            for header in self.checks['headers']['recommended']:
                if header not in headers:
                    result.add_finding({
                        'title': f"Missing {header} Header",
                        'description': f"Recommended security header {header} not found",
                        'risk_level': "Low",
                        'details': {
                            'domain': domain,
                            'header': header
                        },
                        'recommendations': [
                            f"Consider adding {header} header",
                            'Review security header benefits',
                            'Follow security best practices'
                        ]
                    })
                    
        except Exception as e:
            result.add_warning(f"Error checking security headers for {domain}: {str(e)}")

def main():
    """Entry point for SSL scanner"""
    tool = SSLScanner()
    return tool.main()

if __name__ == "__main__":
    main() 