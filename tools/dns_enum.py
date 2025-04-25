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
import dns.dnssec
import dns.message
import dns.rdataclass

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
            name="dns_enum",
            description="DNS Record Enumeration Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        
    def _run_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        """Run DNS enumeration with provided arguments"""
        domain = self.get_param('domain')
        record_types = self.get_param('record_types', 'A,AAAA,MX,NS,TXT,SOA').split(',')
        check_dnssec = self.get_param('check_dnssec', False)
        
        # Enumerate DNS records
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                
                result.add_finding({
                    'title': f'DNS Records: {record_type}',
                    'description': f'Found {len(answers)} {record_type} records',
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'record_type': record_type,
                        'records': [str(rr) for rr in answers]
                    }
                })
                
            except dns.resolver.NXDOMAIN:
                result.add_warning(f"Domain {domain} does not exist")
                return
            except dns.resolver.NoAnswer:
                result.add_info(f"No {record_type} records found for {domain}")
            except Exception as e:
                result.add_error(f"Error querying {record_type} records: {str(e)}")
                
        # Check DNSSEC if requested
        if check_dnssec:
            self._check_dnssec(domain, result)
            
    def _check_dnssec(self, domain: str, result: ToolResult) -> None:
        """Check DNSSEC configuration for domain"""
        try:
            # Check for DNSKEY records
            request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, 
                                          want_dnssec=True)
                                          
            # Get nameservers
            nameservers = self.resolver.resolve(domain, 'NS')
            if not nameservers:
                result.add_warning(f"No nameservers found for {domain}")
                return
                
            # Query first nameserver
            nameserver = str(nameservers[0])
            response = dns.query.udp(request, nameserver)
            
            if response.rcode() != 0:
                result.add_finding({
                    'title': 'DNSSEC Not Configured',
                    'description': f'Domain {domain} does not have DNSSEC configured',
                    'risk_level': 'Medium',
                    'details': {
                        'domain': domain,
                        'nameserver': nameserver
                    },
                    'recommendations': [
                        'Consider implementing DNSSEC to improve DNS security',
                        'Work with your DNS provider to enable DNSSEC'
                    ]
                })
                return
                
            # Check for valid DNSSEC
            answer = response.answer
            if len(answer) >= 2:
                result.add_finding({
                    'title': 'DNSSEC Configured',
                    'description': f'Domain {domain} has DNSSEC properly configured',
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'nameserver': nameserver,
                        'dnskey_records': len(answer[0]),
                        'rrsig_records': len(answer[1])
                    }
                })
            else:
                result.add_finding({
                    'title': 'Invalid DNSSEC Configuration',
                    'description': f'Domain {domain} has incomplete DNSSEC configuration',
                    'risk_level': 'High',
                    'details': {
                        'domain': domain,
                        'nameserver': nameserver
                    },
                    'recommendations': [
                        'Review and fix DNSSEC configuration',
                        'Ensure both DNSKEY and RRSIG records are present',
                        'Validate DNSSEC chain of trust'
                    ]
                })
                
        except Exception as e:
            result.add_error(f"Error checking DNSSEC: {str(e)}")

def main():
    """Entry point for DNS enumeration tool"""
    tool = DNSEnumerator()
    return tool.main()

if __name__ == "__main__":
    main()
        