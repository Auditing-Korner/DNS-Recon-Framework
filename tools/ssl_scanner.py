#!/usr/bin/env python3

import argparse
import json
import socket
import ssl
import logging
import sys
import os
import datetime
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse
import re
import dns.resolver

# Handle imports for framework integration
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class SSLScanner(BaseTool):
    """SSL/TLS security scanner for domains"""
    
    def __init__(self):
        super().__init__(
            name="ssl-scanner",
            description="Comprehensive SSL/TLS configuration and vulnerability scanner"
        )
        self.domain = None
        self.ports = [443]
        self.timeout = 5
        self.threads = 10
        self.check_subdomains = False
        self.subdomains = []
        
        # TLS versions to test
        self.tls_versions = [
            {'name': 'SSLv2', 'version': ssl.PROTOCOL_SSLv23, 'ciphers': 'ALL:!ADH:!LOW:!SSLv2:!SSLv3:!MD5:@STRENGTH', 'is_secure': False, 'threat_level': 'Critical'},
            {'name': 'SSLv3', 'version': ssl.PROTOCOL_SSLv23, 'ciphers': 'ALL:!ADH:!LOW:!SSLv2:!TLSv1:!TLSv1.1:!TLSv1.2:!TLSv1.3:@STRENGTH', 'is_secure': False, 'threat_level': 'Critical'},
            {'name': 'TLSv1.0', 'version': ssl.PROTOCOL_TLSv1, 'ciphers': 'ALL:!ADH:!LOW:@STRENGTH', 'is_secure': False, 'threat_level': 'High'},
            {'name': 'TLSv1.1', 'version': ssl.PROTOCOL_TLSv1_1, 'ciphers': 'ALL:!ADH:!LOW:@STRENGTH', 'is_secure': False, 'threat_level': 'Medium'},
            {'name': 'TLSv1.2', 'version': ssl.PROTOCOL_TLSv1_2, 'ciphers': 'ALL:!ADH:!LOW:@STRENGTH', 'is_secure': True, 'threat_level': 'Low'},
            {'name': 'TLSv1.3', 'version': ssl.PROTOCOL_TLS, 'ciphers': 'ALL:!ADH:!LOW:@STRENGTH', 'is_secure': True, 'threat_level': 'Low'}
        ]
        
        # Weak ciphers to check for
        self.weak_ciphers = [
            "RC4", "DES", "MD5", "NULL", "ADH", "EXPORT", "LOW", "EXP", "anon"
        ]
        
        # Known vulnerabilities to check
        self.vulnerabilities = {
            "BEAST": {
                "description": "Browser Exploit Against SSL/TLS vulnerability",
                "affected_versions": ["SSLv3", "TLSv1.0"],
                "risk_level": "Medium"
            },
            "POODLE": {
                "description": "Padding Oracle On Downgraded Legacy Encryption vulnerability",
                "affected_versions": ["SSLv3"],
                "risk_level": "High"
            },
            "FREAK": {
                "description": "Factoring RSA Export Keys vulnerability",
                "ciphers": ["EXPORT"],
                "risk_level": "Medium"
            },
            "DROWN": {
                "description": "Decrypting RSA with Obsolete and Weakened eNcryption vulnerability",
                "affected_versions": ["SSLv2"],
                "risk_level": "High"
            },
            "Heartbleed": {
                "description": "OpenSSL information disclosure vulnerability",
                "needs_specific_test": True,
                "risk_level": "Critical"
            },
            "ROBOT": {
                "description": "Return Of Bleichenbacher's Oracle Threat vulnerability",
                "needs_specific_test": True,
                "risk_level": "High"
            }
        }
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        super().setup_argparse(parser)
        
        parser.add_argument("domain", help="Domain to scan")
        parser.add_argument("--ports", "-p", default="443", 
                          help="Comma-separated list of ports to scan (default: 443)")
        parser.add_argument("--timeout", "-t", type=int, default=5,
                          help="Connection timeout in seconds (default: 5)")
        parser.add_argument("--threads", type=int, default=10,
                          help="Number of concurrent threads (default: 10)")
        parser.add_argument("--check-subdomains", action="store_true",
                          help="Also check subdomains (if available)")
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the SSL/TLS scanner"""
        # Store arguments
        self.domain = args.domain
        
        # Parse ports
        try:
            self.ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            self.logger.error("Invalid port specification")
            return self._create_error_result("Invalid port specification")
        
        self.timeout = args.timeout
        self.threads = args.threads
        self.check_subdomains = args.check_subdomains
        
        # Create result object
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "scan_date": datetime.datetime.now().isoformat(),
                "domain": self.domain,
                "ports_scanned": self.ports
            }
        )
        
        # Get subdomains if needed
        if self.check_subdomains:
            self.subdomains = self._get_subdomains()
            result.metadata["subdomains_checked"] = len(self.subdomains)
        
        # Prepare targets (domain:port combinations)
        targets = []
        for port in self.ports:
            targets.append((self.domain, port))
            
            # Add subdomains if requested
            if self.check_subdomains:
                for subdomain in self.subdomains:
                    targets.append((subdomain, port))
        
        # Scan all targets
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self._scan_target, target[0], target[1]): target for target in targets}
            
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    scan_result = future.result()
                    if scan_result:
                        host, port, scan_data = scan_result
                        
                        # Add to metadata
                        if "scan_results" not in result.metadata:
                            result.metadata["scan_results"] = []
                        result.metadata["scan_results"].append({
                            "host": host,
                            "port": port,
                            "data": scan_data
                        })
                        
                        # Add findings
                        self._process_findings(result, host, port, scan_data)
                        
                except Exception as e:
                    self.logger.error(f"Error scanning {target[0]}:{target[1]}: {str(e)}")
                    result.add_error(f"Error scanning {target[0]}:{target[1]}: {str(e)}")
        
        return result
    
    def _create_error_result(self, error_message: str) -> ToolResult:
        """Create an error result"""
        result = ToolResult(
            success=False,
            tool_name=self.name,
            findings=[]
        )
        result.add_error(error_message)
        return result
    
    def _get_subdomains(self) -> List[str]:
        """Get subdomains for the target domain"""
        subdomains = []
        try:
            # Try to get common subdomains
            common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 
                               'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 
                               'api', 'dev', 'stage', 'test', 'portal']
            
            for sub in common_subdomains:
                try:
                    fqdn = f"{sub}.{self.domain}"
                    socket.gethostbyname(fqdn)  # Check if resolves
                    subdomains.append(fqdn)
                    self.logger.info(f"Found subdomain: {fqdn}")
                except:
                    pass
            
            # Also check for DNS records that might reveal subdomains
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                for record in ns_records:
                    ns = str(record.target).rstrip('.')
                    if ns not in subdomains and self.domain in ns:
                        subdomains.append(ns)
            except:
                pass
                
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                for record in mx_records:
                    mx = str(record.exchange).rstrip('.')
                    if mx not in subdomains and self.domain in mx:
                        subdomains.append(mx)
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"Error finding subdomains: {str(e)}")
        
        return subdomains
    
    def _scan_target(self, host: str, port: int) -> Optional[Tuple[str, int, Dict[str, Any]]]:
        """Scan a specific host:port target"""
        self.logger.info(f"Scanning {host}:{port}")
        
        result = {
            "supported_protocols": [],
            "certificate": {},
            "ciphers": {},
            "vulnerabilities": []
        }
        
        # Check connectivity first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.close()
        except Exception as e:
            self.logger.warning(f"Cannot connect to {host}:{port}: {str(e)}")
            return None
        
        # Test each TLS/SSL version
        for tls in self.tls_versions:
            try:
                # Create SSL context
                context = ssl.SSLContext(tls['version'])
                context.set_ciphers(tls['ciphers'])
                
                # Create socket and wrap with SSL
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                
                # Try to establish SSL connection
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Connection successful, protocol is supported
                    cipher = ssock.cipher()
                    protocol_version = tls['name']
                    
                    result["supported_protocols"].append({
                        "protocol": protocol_version,
                        "cipher": cipher[0],
                        "bits": cipher[2],
                        "is_secure": tls['is_secure'],
                        "threat_level": tls['threat_level']
                    })
                    
                    # Get certificate info if not already obtained
                    if not result["certificate"]:
                        cert = ssock.getpeercert()
                        if cert:
                            result["certificate"] = self._parse_certificate(cert)
                
                sock.close()
                
                # Check for known vulnerabilities based on protocol version
                for vuln_name, vuln_info in self.vulnerabilities.items():
                    if "affected_versions" in vuln_info and protocol_version in vuln_info["affected_versions"]:
                        result["vulnerabilities"].append({
                            "name": vuln_name,
                            "description": vuln_info["description"],
                            "risk_level": vuln_info["risk_level"],
                            "evidence": f"Server supports {protocol_version}"
                        })
                
            except ssl.SSLError:
                # Protocol not supported (expected for secure configurations)
                continue
            except Exception as e:
                self.logger.debug(f"Error testing {tls['name']} on {host}:{port}: {str(e)}")
                continue
        
        # Check for weak ciphers
        self._check_weak_ciphers(host, port, result)
        
        return (host, port, result)
    
    def _check_weak_ciphers(self, host: str, port: int, result: Dict) -> None:
        """Check for weak cipher support"""
        try:
            # Use OpenSSL-based approach for more complete cipher detection
            weak_ciphers_found = []
            
            for cipher_type in self.weak_ciphers:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                try:
                    # Try to set a specific weak cipher
                    context.set_ciphers(cipher_type)
                    
                    # If we can connect with this cipher, it's supported
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((host, port))
                    
                    try:
                        ssock = context.wrap_socket(sock, server_hostname=host)
                        cipher = ssock.cipher()
                        weak_ciphers_found.append({
                            "name": cipher[0],
                            "type": cipher_type,
                            "bits": cipher[2]
                        })
                        ssock.close()
                    except:
                        pass
                    
                    sock.close()
                except:
                    continue
            
            # Add weak ciphers to result
            if weak_ciphers_found:
                result["weak_ciphers"] = weak_ciphers_found
                
                # Add vulnerability for weak ciphers
                result["vulnerabilities"].append({
                    "name": "Weak Ciphers",
                    "description": "Server supports weak or insecure cipher suites",
                    "risk_level": "High",
                    "evidence": f"Found {len(weak_ciphers_found)} weak ciphers: " + 
                               ", ".join([c['name'] for c in weak_ciphers_found])
                })
                
        except Exception as e:
            self.logger.error(f"Error checking weak ciphers on {host}:{port}: {str(e)}")
    
    def _parse_certificate(self, cert: Dict) -> Dict:
        """Parse SSL certificate information"""
        cert_info = {
            "subject": {},
            "issuer": {},
            "version": cert.get('version', 0),
            "not_before": "",
            "not_after": "",
            "serial_number": cert.get('serialNumber', ""),
            "extensions": []
        }
        
        # Parse subject and issuer
        if 'subject' in cert:
            for item in cert['subject']:
                for key, value in item:
                    cert_info["subject"][key] = value
        
        if 'issuer' in cert:
            for item in cert['issuer']:
                for key, value in item:
                    cert_info["issuer"][key] = value
        
        # Parse validity dates
        if 'notBefore' in cert:
            cert_info["not_before"] = cert['notBefore']
        
        if 'notAfter' in cert:
            cert_info["not_after"] = cert['notAfter']
        
        # Parse extensions
        if 'OCSP' in cert:
            cert_info["extensions"].append({
                "name": "OCSP",
                "value": cert['OCSP']
            })
        
        if 'caIssuers' in cert:
            cert_info["extensions"].append({
                "name": "caIssuers",
                "value": cert['caIssuers']
            })
        
        if 'crlDistributionPoints' in cert:
            cert_info["extensions"].append({
                "name": "CRL",
                "value": cert['crlDistributionPoints']
            })
        
        if 'subjectAltName' in cert:
            cert_info["extensions"].append({
                "name": "subjectAltName",
                "value": cert['subjectAltName']
            })
        
        return cert_info
    
    def _process_findings(self, result: ToolResult, host: str, port: int, scan_data: Dict) -> None:
        """Process scan data and add findings to the result"""
        # Check for insecure protocols
        for protocol in scan_data.get("supported_protocols", []):
            if not protocol.get("is_secure", False):
                result.add_finding(
                    title=f"Insecure Protocol: {protocol['protocol']}",
                    description=f"Server at {host}:{port} supports the insecure {protocol['protocol']} protocol",
                    risk_level=protocol['threat_level'],
                    evidence=f"Detected cipher: {protocol.get('cipher', 'Unknown')}"
                )
        
        # Check certificate validity
        cert = scan_data.get("certificate", {})
        if cert:
            # Check expiration
            try:
                if "not_after" in cert:
                    expiry_date = datetime.datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now()
                    
                    # Certificate is expired
                    if now > expiry_date:
                        result.add_finding(
                            title="Expired SSL Certificate",
                            description=f"The SSL certificate for {host}:{port} has expired",
                            risk_level="High",
                            evidence=f"Expired on: {cert['not_after']}"
                        )
                    # Certificate is about to expire (30 days)
                    elif (expiry_date - now).days < 30:
                        result.add_finding(
                            title="SSL Certificate Expiring Soon",
                            description=f"The SSL certificate for {host}:{port} will expire soon",
                            risk_level="Medium",
                            evidence=f"Expires on: {cert['not_after']}, in {(expiry_date - now).days} days"
                        )
            except:
                pass
            
            # Check certificate subject
            subject = cert.get("subject", {})
            if not subject.get("commonName") or (host != subject.get("commonName") and 
                                               not host.endswith("." + subject.get("commonName", ""))):
                # Check subject alt names
                alt_names = []
                for ext in cert.get("extensions", []):
                    if ext.get("name") == "subjectAltName":
                        alt_names = ext.get("value", "").split(", ")
                        break
                
                valid_for_domain = False
                for name in alt_names:
                    if name.startswith("DNS:"):
                        dns_name = name[4:]
                        if host == dns_name or host.endswith("." + dns_name):
                            valid_for_domain = True
                            break
                
                if not valid_for_domain:
                    result.add_finding(
                        title="SSL Certificate Name Mismatch",
                        description=f"The SSL certificate is not valid for {host}",
                        risk_level="Medium",
                        evidence=f"Certificate CN: {subject.get('commonName', 'Unknown')}"
                    )
        
        # Add findings for detected vulnerabilities
        for vuln in scan_data.get("vulnerabilities", []):
            result.add_finding(
                title=vuln["name"],
                description=vuln["description"],
                risk_level=vuln["risk_level"],
                evidence=vuln.get("evidence", "")
            )
        
        # Check for weak ciphers
        if "weak_ciphers" in scan_data and scan_data["weak_ciphers"]:
            # Main finding was already added in the _check_weak_ciphers method
            pass

def main():
    tool = SSLScanner()
    return tool.main()

if __name__ == "__main__":
    main() 