#!/usr/bin/env python3
"""
DNS Enumeration Tool

Performs comprehensive DNS enumeration and analysis:
- Record enumeration
- Zone transfers
- Subdomain discovery
- DNS security checks
- Infrastructure analysis
"""

import argparse
import concurrent.futures
import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
import socket
import sys
import os
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Common SMTP security issues
SMTP_SECURITY_CHECKS = {
    "open_relay": {
        "ports": [25, 587, 465],
        "test_commands": [
            "HELO test.com",
            "MAIL FROM: test@test.com",
            "RCPT TO: test@test.com",
            "DATA",
            "Subject: Test",
            ".",
            "QUIT"
        ]
    },
    "starttls_required": {
        "ports": [25, 587]
    },
    "banner_check": {
        "dangerous_strings": [
            "postfix",
            "exim",
            "sendmail",
            "microsoft smtp server"
        ]
    }
}

# Common subdomain takeover signatures
TAKEOVER_SIGNATURES = {
    "AWS/S3": {
        "signatures": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "S3 Bucket not found"
        ],
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-[a-z0-9-]+\.amazonaws\.com$"
        ]
    },
    "GitHub Pages": {
        "signatures": [
            "There isn't a GitHub Pages site here",
            "404: Not Found",
            "No such app"
        ],
        "cname_patterns": [
            r"\.github\.io$",
            r"\.githubusercontent\.com$"
        ]
    },
    "Heroku": {
        "signatures": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "Nothing to see here",
            "Building a brand new app"
        ],
        "cname_patterns": [
            r"\.herokuapp\.com$",
            r"\.herokudns\.com$"
        ]
    },
    "Fastly": {
        "signatures": [
            "Fastly error: unknown domain",
            "Unknown domain",
            "Fatal Error"
        ],
        "cname_patterns": [
            r"\.fastly\.net$"
        ]
    }
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS enforces secure (HTTPS) connections to the server",
        "recommended": "max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks",
        "recommended": ["DENY", "SAMEORIGIN"]
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and other injection attacks",
        "recommended": "default-src 'self'"
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering",
        "recommended": "1; mode=block"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information should be included",
        "recommended": ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"]
    },
    "Permissions-Policy": {
        "description": "Controls which features and APIs can be used",
        "recommended": "geolocation=(), microphone=()"
    }
}

# DNS record types to check
RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA', 
    'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'HTTPS', 'SVCB', 'DNAME'
]

# DNSSEC record types to check
DNSSEC_RECORD_TYPES = ['DNSKEY', 'DS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'RRSIG']

# DNSSEC algorithm numbers and their meanings
DNSSEC_ALGORITHMS = {
    0: "Delete DS",
    1: "RSA/MD5 (deprecated)",
    2: "Diffie-Hellman",
    3: "DSA/SHA1",
    5: "RSA/SHA-1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "GOST R 34.10-2001",
    13: "ECDSA Curve P-256 with SHA-256",
    14: "ECDSA Curve P-384 with SHA-384",
    15: "Ed25519",
    16: "Ed448"
}

# DNSSEC digest types
DNSSEC_DIGEST_TYPES = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384"
}

class DNSEnumerator(BaseTool):
    """DNS Enumeration and Analysis Tool"""
    
    def __init__(self):
        super().__init__(
            name="dns-enum",
            description="DNS Enumeration and Analysis Tool"
        )
        self.domain = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
        # Initialize configurations
        self.config = {
            'record_types': RECORD_TYPES,
            'dnssec_types': DNSSEC_RECORD_TYPES,
            'security_headers': SECURITY_HEADERS,
            'takeover_signatures': TAKEOVER_SIGNATURES,
            'smtp_checks': SMTP_SECURITY_CHECKS
        }
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        parser.add_argument('domain', help='Target domain to enumerate')
        parser.add_argument('--check-dnssec', action='store_true',
                          help='Check DNSSEC configuration')
        parser.add_argument('--check-zone-transfer', action='store_true',
                          help='Test for zone transfer vulnerabilities')
        parser.add_argument('--check-smtp', action='store_true',
                          help='Check SMTP security')
        parser.add_argument('--check-headers', action='store_true',
                          help='Check security headers')
        parser.add_argument('--check-takeover', action='store_true',
                          help='Check for subdomain takeover vulnerabilities')
        parser.add_argument('--check-all', action='store_true',
                          help='Run all checks')
        parser.add_argument('--timeout', type=int, default=5,
                          help='Timeout for DNS queries in seconds')
        
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the DNS enumeration"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": args.domain,
                "timestamp": datetime.now().isoformat(),
                "framework_mode": args.framework_mode if hasattr(args, 'framework_mode') else False,
                "checks": {
                    "dnssec": args.check_all or args.check_dnssec,
                    "zone_transfer": args.check_all or args.check_zone_transfer,
                    "smtp": args.check_all or args.check_smtp,
                    "headers": args.check_all or args.check_headers,
                    "takeover": args.check_all or args.check_takeover
                }
            }
        )
        
        try:
            self.domain = args.domain
            self.resolver.timeout = args.timeout
            self.resolver.lifetime = args.timeout
            
            # Always enumerate basic records
            self._enumerate_records(result)
            
            # Run selected checks
            if args.check_all or args.check_dnssec:
                self._check_dnssec(result)
            if args.check_all or args.check_zone_transfer:
                self._check_zone_transfer(result)
            if args.check_all or args.check_smtp:
                self._check_smtp_security(result)
            if args.check_all or args.check_headers:
                self._check_security_headers(result)
            if args.check_all or args.check_takeover:
                self._check_takeover_vulnerabilities(result)
            
            # Add risk summary for framework integration
            if hasattr(args, 'framework_mode') and args.framework_mode:
                risk_summary = {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                }
                for finding in result.findings:
                    risk_summary[finding.get('risk_level', 'Info')] += 1
                result.metadata['risk_summary'] = risk_summary
            
            # Handle output file if specified
            if hasattr(args, 'output') and args.output:
                try:
                    output_dir = os.path.dirname(args.output)
                    if output_dir and not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    
                    with open(args.output, 'w') as f:
                        json.dump(result.to_dict(), f, indent=2)
                except Exception as e:
                    result.add_error(f"Error writing output file: {str(e)}")
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during enumeration: {str(e)}")
            return result
    
    def _enumerate_records(self, result: ToolResult) -> None:
        """Enumerate basic DNS records"""
        try:
            records = {}
            
            for record_type in self.config['record_types']:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    result.add_error(f"Domain {self.domain} does not exist")
                    return
                except Exception as e:
                    result.add_finding(
                        title=f"Error Querying {record_type} Records",
                        description=str(e),
                        risk_level="Low"
                    )
            
            result.metadata["records"] = records
            
        except Exception as e:
            result.add_error(f"Error in record enumeration: {str(e)}")
    
    def _check_dnssec(self, result: ToolResult) -> None:
        """Check DNSSEC configuration"""
        try:
            # Check for DNSSEC records
            dnssec_records = {}
            
            for record_type in self.config['dnssec_types']:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    dnssec_records[record_type] = len(answers)
                except:
                    continue
            
            # Analyze DNSSEC configuration
            if not dnssec_records:
                result.add_finding(
                    title="DNSSEC Not Configured",
                    description="No DNSSEC records found for the domain",
                    risk_level="Medium"
                )
            else:
                # Check for minimum required records
                required_records = {'DNSKEY', 'RRSIG', 'NSEC'}
                missing_records = required_records - set(dnssec_records.keys())
                
                if missing_records:
                    result.add_finding(
                        title="Incomplete DNSSEC Configuration",
                        description=f"Missing DNSSEC records: {', '.join(missing_records)}",
                        risk_level="High"
                    )
                
                # Check DNSKEY if present
                if 'DNSKEY' in dnssec_records:
                    try:
                        dnskey = dns.resolver.resolve(self.domain, 'DNSKEY')
                        for key in dnskey:
                            algorithm = key.algorithm
                            if algorithm in [1, 3, 6, 7]:  # Deprecated algorithms
                                result.add_finding(
                                    title="Deprecated DNSSEC Algorithm",
                                    description=f"Using deprecated algorithm: {DNSSEC_ALGORITHMS.get(algorithm, algorithm)}",
                                    risk_level="High"
                                )
                    except:
                        pass
            
            result.metadata["dnssec"] = dnssec_records
            
        except Exception as e:
            result.add_error(f"Error checking DNSSEC: {str(e)}")
    
    def _check_zone_transfer(self, result: ToolResult) -> None:
        """Check for zone transfer vulnerabilities"""
        try:
            # Get nameservers
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                nameservers = [str(ns.target).rstrip('.') for ns in ns_records]
            except:
                result.add_finding(
                    title="No Nameservers Found",
                    description="Could not find nameservers for domain",
                    risk_level="Medium"
                )
                return
            
            # Try zone transfer from each nameserver
            for ns in nameservers:
                try:
                    # Get nameserver IP
                    ns_ip = socket.gethostbyname(ns)
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain))
                    
                    if zone:
                        result.add_finding(
                            title="Zone Transfer Allowed",
                            description=f"Nameserver {ns} allows zone transfers",
                            risk_level="Critical",
                            evidence=f"Successfully transferred {len(zone.nodes)} records"
                        )
                except:
                    continue
            
        except Exception as e:
            result.add_error(f"Error checking zone transfer: {str(e)}")
    
    def _check_smtp_security(self, result: ToolResult) -> None:
        """Check SMTP security configuration"""
        try:
            # Get MX records
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                mx_hosts = [str(mx.exchange).rstrip('.') for mx in mx_records]
            except:
                result.add_finding(
                    title="No MX Records Found",
                    description="Could not find MX records for domain",
                    risk_level="Medium"
                )
                return
            
            # Check each MX host
            for mx_host in mx_hosts:
                try:
                    # Get IP address
                    mx_ip = socket.gethostbyname(mx_host)
                    
                    # Check open relay
                    for port in self.config['smtp_checks']['open_relay']['ports']:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(self.resolver.timeout)
                            sock.connect((mx_ip, port))
                            
                            # Try relay test
                            for cmd in self.config['smtp_checks']['open_relay']['test_commands']:
                                sock.send(f"{cmd}\r\n".encode())
                                response = sock.recv(1024).decode()
                                
                                if "250" in response and cmd == "RCPT TO: test@test.com":
                                    result.add_finding(
                                        title="Open SMTP Relay",
                                        description=f"Mail server {mx_host}:{port} appears to be an open relay",
                                        risk_level="Critical",
                                        evidence=f"Server accepted relay test: {response}"
                                    )
                            
                            sock.close()
                        except:
                            continue
                    
                    # Check STARTTLS
                    for port in self.config['smtp_checks']['starttls_required']['ports']:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(self.resolver.timeout)
                            sock.connect((mx_ip, port))
                            
                            # Check if STARTTLS is advertised
                            sock.send(b"EHLO test.com\r\n")
                            response = sock.recv(1024).decode()
                            
                            if "STARTTLS" not in response:
                                result.add_finding(
                                    title="STARTTLS Not Available",
                                    description=f"Mail server {mx_host}:{port} does not support STARTTLS",
                                    risk_level="High",
                                    evidence=response
                                )
                            
                            sock.close()
                        except:
                            continue
                    
                except Exception as e:
                    result.add_finding(
                        title=f"Error Checking SMTP Security for {mx_host}",
                        description=str(e),
                        risk_level="Low"
                    )
            
        except Exception as e:
            result.add_error(f"Error checking SMTP security: {str(e)}")
    
    def _check_security_headers(self, result: ToolResult) -> None:
        """Check security headers"""
        try:
            import requests
            from urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
            
            # Try both HTTPS and HTTP
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(
                        f"{protocol}://{self.domain}",
                        timeout=self.resolver.timeout,
                        verify=False
                    )
                    
                    # Check each security header
                    for header, config in self.config['security_headers'].items():
                        value = response.headers.get(header)
                        
                        if not value:
                            result.add_finding(
                                title=f"Missing Security Header: {header}",
                                description=config['description'],
                                risk_level="Medium",
                                evidence=f"Header not present in {protocol.upper()} response"
                            )
                        elif isinstance(config['recommended'], list):
                            if not any(rec in value for rec in config['recommended']):
                                result.add_finding(
                                    title=f"Misconfigured Security Header: {header}",
                                    description=f"Value does not match recommended settings: {config['recommended']}",
                                    risk_level="Low",
                                    evidence=f"Current value: {value}"
                                )
                        elif value != config['recommended']:
                            result.add_finding(
                                title=f"Misconfigured Security Header: {header}",
                                description=f"Value does not match recommended setting: {config['recommended']}",
                                risk_level="Low",
                                evidence=f"Current value: {value}"
                            )
                    
                    break  # Stop if we get a successful response
                    
                except requests.RequestException:
                    continue
            
        except Exception as e:
            result.add_error(f"Error checking security headers: {str(e)}")
    
    def _check_takeover_vulnerabilities(self, result: ToolResult) -> None:
        """Check for subdomain takeover vulnerabilities"""
        try:
            # Get CNAME records
            cname_records = {}
            try:
                answers = dns.resolver.resolve(self.domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    cname_records[self.domain] = cname
            except:
                pass
            
            # Check each CNAME
            for domain, cname in cname_records.items():
                # Check against known patterns
                for provider, config in self.config['takeover_signatures'].items():
                    for pattern in config['cname_patterns']:
                        if re.search(pattern, cname, re.IGNORECASE):
                            # Try to resolve CNAME
                            try:
                                socket.gethostbyname(cname)
                            except socket.gaierror:
                                # CNAME doesn't resolve - potential takeover
                                result.add_finding(
                                    title="Potential Subdomain Takeover",
                                    description=f"Domain points to unregistered {provider} resource",
                                    risk_level="Critical",
                                    evidence=f"CNAME: {cname}, Pattern: {pattern}"
                                )
                                break
            
        except Exception as e:
            result.add_error(f"Error checking takeover vulnerabilities: {str(e)}")

def main():
    """Main function for standalone usage"""
    tool = DNSEnumerator()
    parser = argparse.ArgumentParser(description=tool.description)
    tool.setup_argparse(parser)
    args = parser.parse_args()
    
    result = tool.run(args)
    
    if args.output:
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(result.to_dict(), indent=2))
    
    sys.exit(0 if result.success else 1)

if __name__ == "__main__":
    main()
        