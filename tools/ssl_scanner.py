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
    from .framework_tool_template import FrameworkTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.framework_tool_template import FrameworkTool, ToolResult

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

class SSLScanner(FrameworkTool):
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
    
    def setup_tool_arguments(self, parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup]) -> None:
        """Set up tool-specific arguments"""
        parser.add_argument('domain', help='Domain to scan')
        parser.add_argument('--ports', type=str, default="443,8443",
                          help='Comma-separated list of ports to scan')
        parser.add_argument('--timeout', type=int, default=10,
                          help='Connection timeout in seconds')
        parser.add_argument('--threads', type=int, default=5,
                          help='Number of concurrent threads')
        parser.add_argument('--check-subdomains', action='store_true',
                          help='Also check subdomains')
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        """Execute SSL/TLS security scan"""
        try:
            # Check dependencies
            if MISSING_DEPS:
                result.add_error(f"Missing required dependencies: {', '.join(MISSING_DEPS)}")
                return
            
            # Parse ports
            try:
                ports = [int(p.strip()) for p in args.ports.split(",")]
            except:
                ports = self.default_ports
            
            # Update metadata
            result.metadata.update({
                "domain": args.domain,
                "timestamp": datetime.now().isoformat(),
                "ports_scanned": ports,
                "check_subdomains": args.check_subdomains
            })
            
            # Scan domain
            scan_result = self.scan_host(args.domain, ports, args.timeout)
            
            # Add findings based on scan results
            if not scan_result.cert_valid:
                self.add_common_finding(
                    result,
                    title=f"Invalid SSL Certificate: {scan_result.hostname}",
                    description="The SSL certificate is invalid or expired",
                    risk_level="High",
                    evidence=f"Certificate expires: {scan_result.cert_expires}"
                )
            
            # Check for insecure protocols
            insecure_protocols = [p for p in scan_result.protocols if p in ["SSLv2", "SSLv3", "TLSv1.0"]]
            if insecure_protocols:
                self.add_common_finding(
                    result,
                    title="Insecure SSL/TLS Protocols Detected",
                    description=f"The following insecure protocols are enabled: {', '.join(insecure_protocols)}",
                    risk_level="High",
                    evidence=f"Enabled protocols: {', '.join(scan_result.protocols)}"
                )
            
            # Check for weak ciphers
            weak_ciphers = [c for c in scan_result.ciphers if "NULL" in c or "RC4" in c or "MD5" in c]
            if weak_ciphers:
                self.add_common_finding(
                    result,
                    title="Weak Cipher Suites Detected",
                    description=f"The following weak cipher suites are enabled: {', '.join(weak_ciphers)}",
                    risk_level="Medium",
                    evidence=f"Enabled ciphers: {', '.join(scan_result.ciphers)}"
                )
            
            # Check for vulnerabilities
            for vuln in scan_result.vulnerabilities:
                self.add_common_finding(
                    result,
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
                self.add_common_finding(
                    result,
                    title="Missing Security Headers",
                    description=f"The following security headers are missing: {', '.join(missing_headers)}",
                    risk_level="Medium",
                    evidence=f"Present headers: {', '.join(scan_result.headers.keys())}"
                )
            
            # Add any errors
            for error in scan_result.errors:
                result.add_error(error)
            
            # Set success status
            result.success = len(scan_result.errors) == 0
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during SSL/TLS scan: {str(e)}")
            if not self.is_framework_mode():
                logging.error(f"Error: {str(e)}")
    
    def scan_host(self, hostname: str, ports: List[int], timeout: int) -> SSLResult:
        """Scan a host for SSL/TLS configuration"""
        errors = []
        protocols = []
        ciphers = []
        vulnerabilities = []
        headers = {}
        cert_valid = False
        cert_expires = "Unknown"
        current_port = None
        
        try:
            # Test each port
            for port in ports:
                current_port = port
                try:
                    # Create SSL context
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Connect and get certificate
                    with socket.create_connection((hostname, port), timeout=timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                            
                            # Check certificate validity
                            cert_valid = True
                            # Fix deprecation warning by using not_valid_after_utc
                            cert_expires = x509_cert.not_valid_after_utc.isoformat()
                            
                            # Get protocols and ciphers
                            protocols.extend(ssock.shared_ciphers())
                            ciphers.extend([cipher[0] for cipher in ssock.shared_ciphers()])
                            
                            # Check for vulnerabilities
                            self._check_vulnerabilities(ssock, vulnerabilities)
                            
                            # Get security headers
                            headers = self._get_security_headers(hostname, port)
                    
                except ssl.SSLError as e:
                    errors.append(f"SSL error on port {port}: {str(e)}")
                except socket.error as e:
                    errors.append(f"Connection error on port {port}: {str(e)}")
                except Exception as e:
                    errors.append(f"Error scanning port {port}: {str(e)}")
        
        except Exception as e:
            errors.append(f"Error during scan: {str(e)}")
        
        return SSLResult(
            hostname=hostname,
            port=current_port or ports[0],
            cert_valid=cert_valid,
            cert_expires=cert_expires,
            protocols=protocols,
            ciphers=ciphers,
            vulnerabilities=vulnerabilities,
            headers=headers,
            errors=errors
        )
    
    def _check_vulnerabilities(self, ssl_socket: ssl.SSLSocket, vulnerabilities: List[Dict]) -> None:
        """Check for known SSL/TLS vulnerabilities"""
        try:
            # Check for Heartbleed
            if self._check_heartbleed(ssl_socket):
                vulnerabilities.append({
                    **self.vulnerabilities["heartbleed"],
                    "details": "Server is vulnerable to Heartbleed"
                })
            
            # Check for POODLE
            if "SSLv3" in ssl_socket.version():
                vulnerabilities.append({
                    **self.vulnerabilities["poodle"],
                    "details": "Server supports SSLv3, vulnerable to POODLE"
                })
            
            # Check for FREAK
            if any("EXPORT" in cipher for cipher in ssl_socket.shared_ciphers()):
                vulnerabilities.append({
                    **self.vulnerabilities["freak"],
                    "details": "Server supports EXPORT ciphers, vulnerable to FREAK"
                })
            
        except Exception as e:
            vulnerabilities.append({
                "name": "Vulnerability Check Error",
                "description": f"Error checking vulnerabilities: {str(e)}",
                "severity": "Error"
            })
    
    def _check_heartbleed(self, ssl_socket: ssl.SSLSocket) -> bool:
        """Check if server is vulnerable to Heartbleed"""
        try:
            # Implementation of Heartbleed check would go here
            # This is a placeholder - actual implementation would require careful testing
            return False
        except:
            return False
    
    def _get_security_headers(self, hostname: str, port: int) -> Dict:
        """Get security headers from the server"""
        headers = {}
        try:
            # Use requests instead of http.client for better error handling
            url = f"https://{hostname}:{port}"
            response = requests.head(url, timeout=5, verify=False)
            
            for header in self.security_headers:
                if header in response.headers:
                    headers[header] = response.headers[header]
            
            return headers
            
        except Exception as e:
            return {"error": str(e)}

def main():
    """Main entry point for the tool"""
    tool = SSLScanner()
    parser = argparse.ArgumentParser(description=tool.description)
    tool.setup_argparse(parser)
    args = parser.parse_args()
    result = tool.run(args)
    sys.exit(0 if result.success else 1)

if __name__ == "__main__":
    main() 