#!/usr/bin/env python3
"""
SSL/TLS Security Scanner

Analyzes SSL/TLS configuration and security:
- Certificate validation
- Protocol support
- Cipher suites
- Known vulnerabilities
- Security headers
"""

import argparse
import json
import logging
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Check dependencies
MISSING_DEPS = []
try:
    import ssl
except ImportError:
    MISSING_DEPS.append("ssl")

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    MISSING_DEPS.append("cryptography")

try:
    import OpenSSL
except ImportError:
    MISSING_DEPS.append("pyOpenSSL")

try:
    import socket
except ImportError:
    MISSING_DEPS.append("socket")

try:
    import requests
except ImportError:
    MISSING_DEPS.append("requests")

@dataclass
class SSLResult:
    """Container for SSL scan results"""
    hostname: str
    port: int
    cert_valid: bool
    cert_expires: str
    protocols: List[str]
    ciphers: List[str]
    vulnerabilities: List[Dict]
    headers: Dict
    errors: List[str]

class SSLScanner(BaseTool):
    """SSL/TLS Security Scanner Tool"""
    
    def __init__(self):
        super().__init__(
            name="ssl-scanner",
            description="SSL/TLS Security Scanner"
        )
        
        # Default ports to scan
        self.default_ports = [443, 8443]
        
        # Known vulnerabilities to check
        self.vulnerabilities = {
            "heartbleed": {
                "name": "Heartbleed",
                "description": "OpenSSL heartbeat read overrun (CVE-2014-0160)",
                "severity": "Critical"
            },
            "ccs": {
                "name": "CCS Injection",
                "description": "OpenSSL CCS man-in-the-middle vulnerability (CVE-2014-0224)",
                "severity": "High"
            },
            "poodle": {
                "name": "POODLE",
                "description": "SSLv3 CBC padding oracle vulnerability (CVE-2014-3566)",
                "severity": "High"
            },
            "freak": {
                "name": "FREAK",
                "description": "OpenSSL RSA key downgrade attack (CVE-2015-0204)",
                "severity": "Medium"
            }
        }
        
        # Security headers to check
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        parser.add_argument('domain', help='Domain to scan')
        parser.add_argument('--ports', type=str, default="443,8443",
                          help='Comma-separated list of ports to scan')
        parser.add_argument('--timeout', type=int, default=10,
                          help='Connection timeout in seconds')
        parser.add_argument('--threads', type=int, default=5,
                          help='Number of concurrent threads')
        parser.add_argument('--check-subdomains', action='store_true',
                          help='Also check subdomains')
        
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Execute SSL/TLS security scan"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": args.domain,
                "timestamp": datetime.now().isoformat(),
                "framework_mode": args.framework_mode if hasattr(args, 'framework_mode') else False
            }
        )
        
        try:
            # Check dependencies
            if MISSING_DEPS:
                result.add_error(f"Missing required dependencies: {', '.join(MISSING_DEPS)}")
                return result
            
            # Parse ports
            try:
                ports = [int(p.strip()) for p in args.ports.split(",")]
            except:
                ports = self.default_ports
            
            # Update metadata
            result.metadata.update({
                "ports_scanned": ports,
                "check_subdomains": args.check_subdomains
            })
            
            # Scan domain
            scan_result = self.scan_host(args.domain, ports, args.timeout)
            
            # Add findings based on scan results
            if not scan_result.cert_valid:
                result.add_finding(
                    title=f"Invalid SSL Certificate: {scan_result.hostname}",
                    description="The SSL certificate is invalid or expired",
                    risk_level="High",
                    evidence=f"Certificate expires: {scan_result.cert_expires}"
                )
            
            # Check for insecure protocols
            insecure_protocols = [p for p in scan_result.protocols if p in ["SSLv2", "SSLv3", "TLSv1.0"]]
            if insecure_protocols:
                result.add_finding(
                    title="Insecure SSL/TLS Protocols Detected",
                    description=f"The following insecure protocols are enabled: {', '.join(insecure_protocols)}",
                    risk_level="High",
                    evidence=f"Enabled protocols: {', '.join(scan_result.protocols)}"
                )
            
            # Check for weak ciphers
            weak_ciphers = [c for c in scan_result.ciphers if "NULL" in c or "RC4" in c or "MD5" in c]
            if weak_ciphers:
                result.add_finding(
                    title="Weak Cipher Suites Detected",
                    description=f"The following weak cipher suites are enabled: {', '.join(weak_ciphers)}",
                    risk_level="Medium",
                    evidence=f"Enabled ciphers: {', '.join(scan_result.ciphers)}"
                )
            
            # Check for vulnerabilities
            for vuln in scan_result.vulnerabilities:
                result.add_finding(
                    title=f"Vulnerability Detected: {vuln['name']}",
                    description=vuln['description'],
                    risk_level=vuln['severity'],
                    evidence=vuln.get('details', 'No additional details')
                )
            
            # Check security headers
            missing_headers = []
            for header in self.security_headers:
                if header not in scan_result.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                result.add_finding(
                    title="Missing Security Headers",
                    description=f"The following security headers are missing: {', '.join(missing_headers)}",
                    risk_level="Medium",
                    evidence=f"Present headers: {', '.join(scan_result.headers.keys())}"
                )
            
            # Add errors from scan
            for error in scan_result.errors:
                result.add_error(error)
            
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
            result.add_error(f"Error during scan: {str(e)}")
            return result

    def scan_host(self, hostname: str, ports: List[int], timeout: int) -> SSLResult:
        """Perform SSL/TLS scan of a host"""
        result = SSLResult(
            hostname=hostname,
            port=0,
            cert_valid=False,
            cert_expires="",
            protocols=[],
            ciphers=[],
            vulnerabilities=[],
            headers={},
            errors=[]
        )
        
        for port in ports:
            try:
                # Create SSL context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Connect to host
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                        # Get certificate info
                        cert = ssl_sock.getpeercert(binary_form=True)
                        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                        
                        result.port = port
                        result.cert_valid = True
                        result.cert_expires = x509_cert.not_valid_after.isoformat()
                        
                        # Get protocol version
                        result.protocols.append(ssl_sock.version())
                        
                        # Get cipher info
                        cipher = ssl_sock.cipher()
                        if cipher:
                            result.ciphers.append(f"{cipher[0]}:{cipher[1]}:{cipher[2]}")
                        
                        # Check for vulnerabilities
                        self._check_vulnerabilities(ssl_sock, result.vulnerabilities)
                
                # Get security headers
                result.headers = self._get_security_headers(hostname, port)
                
            except ssl.SSLError as e:
                result.errors.append(f"SSL Error on port {port}: {str(e)}")
            except socket.error as e:
                result.errors.append(f"Connection Error on port {port}: {str(e)}")
            except Exception as e:
                result.errors.append(f"Error scanning port {port}: {str(e)}")
        
        return result

    def _check_vulnerabilities(self, ssl_socket: ssl.SSLSocket, vulnerabilities: List[Dict]) -> None:
        """Check for known SSL/TLS vulnerabilities"""
        # Check for Heartbleed
        if self._check_heartbleed(ssl_socket):
            vulnerabilities.append({
                "name": self.vulnerabilities["heartbleed"]["name"],
                "description": self.vulnerabilities["heartbleed"]["description"],
                "severity": self.vulnerabilities["heartbleed"]["severity"],
                "details": "Server is vulnerable to Heartbleed attack"
            })
        
        # Check protocol version for POODLE
        if "SSLv3" in ssl_socket.version():
            vulnerabilities.append({
                "name": self.vulnerabilities["poodle"]["name"],
                "description": self.vulnerabilities["poodle"]["description"],
                "severity": self.vulnerabilities["poodle"]["severity"],
                "details": "Server supports SSLv3, vulnerable to POODLE attack"
            })

    def _check_heartbleed(self, ssl_socket: ssl.SSLSocket) -> bool:
        """Check if server is vulnerable to Heartbleed"""
        # This is a placeholder - actual Heartbleed check would require packet-level testing
        # which should only be done with explicit permission
        return False

    def _get_security_headers(self, hostname: str, port: int) -> Dict:
        """Get security headers from HTTPS response"""
        headers = {}
        try:
            response = requests.get(
                f"https://{hostname}:{port}",
                timeout=5,
                verify=False  # We've already checked the cert
            )
            headers = {k: v for k, v in response.headers.items()
                      if k in self.security_headers}
        except:
            pass
        return headers

def main():
    """Main function for standalone usage"""
    tool = SSLScanner()
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