#!/usr/bin/env python3
"""
SSL Scan Wrapper Tool

Combines our internal SSL scanner with the external sslscan tool for comprehensive SSL/TLS testing:
- Internal SSL/TLS protocol checks
- Certificate validation
- Cipher suite analysis
- Known vulnerability detection
- Integration with sslscan for additional checks
"""

import argparse
import concurrent.futures
import json
import subprocess
import sys
import os
import re
import logging
from typing import Dict, List, Optional, Union
from datetime import datetime
from pathlib import Path

try:
    from .base_tool import BaseTool, ToolResult
    from .ssl_scanner import SSLScanner
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult
    from tools.ssl_scanner import SSLScanner

class SSLScanWrapper:
    """Wrapper combining internal SSL scanner with external sslscan tool"""
    
    def __init__(self):
        self.name = "ssl-scan-wrapper"
        self.description = "Comprehensive SSL/TLS scanner with sslscan integration"
        self.internal_scanner = SSLScanner()
        self.sslscan_path = "sslscan"  # Default to system PATH
        self.domain = None
        self.ports = [443]
        self.timeout = 5
        self.verify_ssl = False
        
        # Set up logging
        self.logger = logging.getLogger(self.name)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        # sslscan output patterns
        self.sslscan_patterns = {
            'protocols': re.compile(r'(SSL|TLS)\s+(v\d+\.\d+)\s+(\w+)'),
            'ciphers': re.compile(r'(\d+)\s+bits\s+(\w+)\s+([A-Z0-9-]+)'),
            'cert_info': re.compile(r'Subject:\s+(.+)[\r\n]+Issuer:\s+(.+)[\r\n]+Expiry:'),
            'vulnerabilities': {
                'heartbleed': re.compile(r'Heartbleed:\s+(.+)'),
                'ccs': re.compile(r'CCS:\s+(.+)'),
                'renegotiation': re.compile(r'Secure Renegotiation:\s+(.+)'),
                'compression': re.compile(r'Compression:\s+(.+)')
            }
        }

    def parse_args(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument('domain', help='Target domain to scan')
        parser.add_argument('--ports', '-p', default='443',
                          help='Comma-separated list of ports to scan (default: 443)')
        parser.add_argument('--timeout', '-t', type=int, default=5,
                          help='Connection timeout in seconds (default: 5)')
        parser.add_argument('--sslscan-path', default='sslscan',
                          help='Path to sslscan executable')
        parser.add_argument('--internal-only', action='store_true',
                          help='Only use internal scanner (skip sslscan)')
        parser.add_argument('--verify-ssl', action='store_true',
                          help='Verify SSL certificates')
        parser.add_argument('--json-output', action='store_true',
                          help='Output results in JSON format')
        parser.add_argument('--verbose', action='store_true',
                          help='Enable verbose output')
        parser.add_argument('--quiet', action='store_true',
                          help='Suppress all output except errors')
        return parser.parse_args()

    def run(self, args) -> Dict:
        """Run SSL scans"""
        # Set logging level based on verbosity
        if args.quiet:
            self.logger.setLevel(logging.ERROR)
        elif args.verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": args.domain,
                "scan_date": datetime.now().isoformat()
            }
        )
        
        try:
            # Store configuration
            self.domain = args.domain
            self.ports = [int(p.strip()) for p in args.ports.split(',')]
            self.timeout = args.timeout
            self.sslscan_path = args.sslscan_path
            self.verify_ssl = args.verify_ssl
            
            self.logger.debug(f"Starting scan of {self.domain} on ports {self.ports}")
            
            # Run internal scanner
            internal_result = self._run_internal_scan(args)
            if internal_result:
                result.findings.extend(internal_result.findings)
                result.metadata["internal_scan"] = internal_result.metadata
                self.logger.debug("Internal scan completed successfully")
            else:
                self.logger.warning("Internal scan failed or returned no results")
            
            # Try external sslscan if not disabled
            if not args.internal_only:
                try:
                    self.logger.debug("Attempting external sslscan")
                    external_findings = self._run_sslscan()
                    if external_findings:
                        result.findings.extend(external_findings)
                        result.metadata["external_scan"] = {
                            "tool": "sslscan",
                            "version": self._get_sslscan_version()
                        }
                        self.logger.debug("External scan completed successfully")
                except Exception as e:
                    self.logger.warning(f"External scan failed: {str(e)}")
                    result.add_finding(
                        title="External SSLScan Not Available",
                        description="Could not run external sslscan tool. Using internal scanner only.",
                        risk_level="Info",
                        evidence=str(e)
                    )
            
            # Add recommendation if no external scan
            if not result.metadata.get("external_scan"):
                result.add_finding(
                    title="External SSL Scan Recommended",
                    description="For more comprehensive results, install sslscan tool and run without --internal-only flag",
                    risk_level="Info",
                    evidence="https://github.com/rbsec/sslscan"
                )
            
            # Merge and deduplicate findings
            result.findings = self._deduplicate_findings(result.findings)
            self.logger.debug(f"Scan completed with {len(result.findings)} findings")
            
            # Print results unless quiet mode is enabled
            if not args.quiet:
                if args.json_output:
                    print(json.dumps(result.to_dict(), indent=2))
                else:
                    self._print_results(result)
            
            return result.to_dict()
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'tool_name': self.name
            }

    def _run_internal_scan(self, args) -> Optional[ToolResult]:
        """Run the internal SSL scanner"""
        try:
            # Create a temporary namespace with required attributes
            internal_args = argparse.Namespace()
            internal_args.domain = args.domain
            internal_args.ports = args.ports
            internal_args.timeout = args.timeout
            internal_args.verify_ssl = args.verify_ssl
            internal_args.json = args.json_output
            internal_args.check_all = True
            internal_args.check_spf = True
            internal_args.check_dmarc = True
            internal_args.check_dkim = True
            internal_args.check_ttl = True
            internal_args.threads = 10  # Default value
            internal_args.output = None
            internal_args.format = 'json'
            internal_args.verbose = args.verbose
            internal_args.quiet = args.quiet
            internal_args.force = False
            internal_args.framework_mode = False
            internal_args.output_format = 'json'
            internal_args.check_subdomains = False
            
            # Run internal scan
            return self.internal_scanner.run(internal_args)
            
        except Exception as e:
            self.logger.error(f"Error in internal scan: {str(e)}")
            return None

    def _run_sslscan(self) -> List[Dict]:
        """Run external sslscan tool and parse results"""
        findings = []
        
        try:
            # Check if sslscan is available
            version = self._get_sslscan_version()
            if not version:
                raise FileNotFoundError("sslscan not found in PATH")
            
            self.logger.debug(f"Found sslscan version: {version}")
            
            # Run sslscan for each port
            for port in self.ports:
                try:
                    cmd = [
                        self.sslscan_path,
                        '--no-colour',
                        '--show-certificate',
                        '--show-ciphers',
                        '--show-client-ciphers',
                        '--show-protocols',
                        '--show-times',
                        f"{self.domain}:{port}"
                    ]
                    
                    self.logger.debug(f"Running command: {' '.join(cmd)}")
                    process = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                    output = process.stdout
                    
                    # Parse sslscan output
                    findings.extend(self._parse_sslscan_output(output, port))
                    
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Scan timeout on port {port}")
                    findings.append({
                        'title': f'SSLScan Timeout on Port {port}',
                        'description': f'External scan timed out after {self.timeout} seconds',
                        'risk_level': 'Low',
                        'evidence': f"Command: {' '.join(cmd)}"
                    })
                except subprocess.SubprocessError as e:
                    self.logger.warning(f"Scan error on port {port}: {str(e)}")
                    findings.append({
                        'title': f'SSLScan Error on Port {port}',
                        'description': f'Error running external scan: {str(e)}',
                        'risk_level': 'Low',
                        'evidence': f"Command: {' '.join(cmd)}"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error running sslscan: {str(e)}")
            findings.append({
                'title': 'SSLScan Execution Error',
                'description': f'Error executing external scan: {str(e)}',
                'risk_level': 'Low',
                'evidence': f"Domain: {self.domain}, Ports: {self.ports}"
            })
        
        return findings

    def _get_sslscan_version(self) -> Optional[str]:
        """Get sslscan version"""
        try:
            process = subprocess.run([self.sslscan_path, '--version'],
                                  capture_output=True, text=True, check=True)
            match = re.search(r'(\d+\.\d+\.\d+)', process.stdout)
            return match.group(1) if match else None
        except:
            return None

    def _parse_sslscan_output(self, output: str, port: int) -> List[Dict]:
        """Parse sslscan output and convert to findings"""
        findings = []
        
        # Check protocols
        for match in self.sslscan_patterns['protocols'].finditer(output):
            protocol_type, version, status = match.groups()
            if status.lower() == 'enabled' and protocol_type == 'SSL':
                findings.append({
                    'title': f'Insecure Protocol Enabled on Port {port}',
                    'description': f'{protocol_type} {version} is enabled and considered insecure',
                    'risk_level': 'High',
                    'evidence': f"Protocol: {protocol_type} {version}, Status: {status}"
                })
        
        # Check weak ciphers
        for match in self.sslscan_patterns['ciphers'].finditer(output):
            bits, cipher_type, cipher_name = match.groups()
            if int(bits) < 128 or 'NULL' in cipher_name or 'anon' in cipher_name:
                findings.append({
                    'title': f'Weak Cipher Supported on Port {port}',
                    'description': f'Server supports weak cipher: {cipher_name}',
                    'risk_level': 'High',
                    'evidence': f"Cipher: {cipher_name}, Bits: {bits}, Type: {cipher_type}"
                })
        
        # Check vulnerabilities
        for vuln_name, pattern in self.sslscan_patterns['vulnerabilities'].items():
            match = pattern.search(output)
            if match:
                status = match.group(1)
                if 'vulnerable' in status.lower() or 'enabled' in status.lower():
                    findings.append({
                        'title': f'{vuln_name.title()} Vulnerability on Port {port}',
                        'description': f'Server is vulnerable to {vuln_name}',
                        'risk_level': 'Critical',
                        'evidence': f"Status: {status}"
                    })
        
        return findings

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings based on title and description"""
        seen = set()
        deduped = []
        
        for finding in findings:
            key = (finding['title'], finding['description'])
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        
        return deduped

    def _print_results(self, result: ToolResult) -> None:
        """Print results in a human-readable format"""
        print(f"\n=== {self.name.upper()} Results ===\n")
        
        if result.metadata:
            print("Metadata:")
            for key, value in result.metadata.items():
                print(f"  {key}: {value}")
            print()
        
        if result.findings:
            print("Findings:")
            for finding in result.findings:
                print(f"\n[{finding['risk_level']}] {finding['title']}")
                print(f"Description: {finding['description']}")
                if 'evidence' in finding:
                    print(f"Evidence: {finding['evidence']}")
        
        if result.errors:
            print("\nErrors:")
            for error in result.errors:
                print(f"  - {error['message']}")
        
        print(f"\nExecution time: {datetime.now() - result.start_time}")
        print(f"Status: {'Success' if result.success else 'Failed'}\n")

def main():
    tool = SSLScanWrapper()
    args = tool.parse_args()
    result = tool.run(args)
    return result['status'] if result and 'status' in result else 'error'

if __name__ == "__main__":
    sys.exit(0 if main() == 'success' else 1) 