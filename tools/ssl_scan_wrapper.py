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

class SSLScanWrapper(BaseTool):
    """Wrapper combining internal SSL scanner with external sslscan tool"""
    
    def __init__(self):
        super().__init__(
            name="ssl-scan-wrapper",
            description="Comprehensive SSL/TLS scanner with sslscan integration"
        )
        self.internal_scanner = SSLScanner()
        self.sslscan_path = "sslscan"  # Default to system PATH
        self.domain = None
        self.ports = [443]
        self.timeout = 5
        self.verify_ssl = False
        
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

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        super().setup_argparse(parser)
        
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

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run both internal and external SSL scans"""
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
            
            # Run internal scanner
            internal_result = self._run_internal_scan(args)
            if internal_result:
                result.findings.extend(internal_result.findings)
                result.metadata["internal_scan"] = internal_result.metadata
            
            # Run external sslscan if available and not disabled
            if not args.internal_only:
                external_findings = self._run_sslscan()
                if external_findings:
                    result.findings.extend(external_findings)
            
            # Merge and deduplicate findings
            result.findings = self._deduplicate_findings(result.findings)
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during scan: {str(e)}")
            return result

    def _run_internal_scan(self, args: argparse.Namespace) -> Optional[ToolResult]:
        """Run the internal SSL scanner"""
        try:
            # Configure internal scanner
            internal_args = argparse.Namespace(
                domain=self.domain,
                ports=args.ports,
                timeout=self.timeout,
                check_all=True,
                verify_ssl=self.verify_ssl,
                json=args.json_output
            )
            
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
            try:
                subprocess.run([self.sslscan_path, '--version'], 
                             capture_output=True, text=True, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                findings.append({
                    'title': 'SSLScan Not Available',
                    'description': 'External sslscan tool is not available or not executable',
                    'risk_level': 'Info',
                    'evidence': f"Tried to execute: {self.sslscan_path}"
                })
                return findings
            
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
                    
                    process = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                    output = process.stdout
                    
                    # Parse sslscan output
                    findings.extend(self._parse_sslscan_output(output, port))
                    
                except subprocess.TimeoutExpired:
                    findings.append({
                        'title': f'SSLScan Timeout on Port {port}',
                        'description': f'External scan timed out after {self.timeout} seconds',
                        'risk_level': 'Low',
                        'evidence': f"Command: {' '.join(cmd)}"
                    })
                except subprocess.SubprocessError as e:
                    findings.append({
                        'title': f'SSLScan Error on Port {port}',
                        'description': f'Error running external scan: {str(e)}',
                        'risk_level': 'Low',
                        'evidence': f"Command: {' '.join(cmd)}"
                    })
                    
        except Exception as e:
            findings.append({
                'title': 'SSLScan Execution Error',
                'description': f'Error executing external scan: {str(e)}',
                'risk_level': 'Low',
                'evidence': f"Domain: {self.domain}, Ports: {self.ports}"
            })
        
        return findings

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

def main():
    tool = SSLScanWrapper()
    return tool.main()

if __name__ == "__main__":
    sys.exit(0 if main() == 'success' else 1) 