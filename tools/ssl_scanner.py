#!/usr/bin/env python3

"""SSL/TLS Scanner for RFS DNS Framework."""

import logging
import socket
from typing import Dict, List, Optional, Any
from datetime import datetime

import sslyze
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.models import ServerScanRequest, ServerNetworkLocation
from sslyze.scanner.scanner import Scanner
from sslyze.errors import ConnectionToServerFailed

try:
    from tools.base_tool import BaseTool
    from tools.utils import is_valid_domain
except ImportError:
    # Handle case when running as standalone script
    import os
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool
    from tools.utils import is_valid_domain

# Tool configuration
TOOL_CONFIG = {
    'name': 'ssl_scanner',
    'description': 'Analyze SSL/TLS configurations and certificates',
    'critical': False,
    'requires_root': False,
    'order': 5
}

class SSLScannerTool(BaseTool):
    """Tool for scanning SSL/TLS configurations and certificates."""
    
    def __init__(self):
        """Initialize the SSL Scanner tool."""
        super().__init__(name=TOOL_CONFIG['name'], description=TOOL_CONFIG['description'])
        self.findings = []
        self.logger = logging.getLogger(__name__)

    def validate_args(self, args: Dict[str, Any]) -> bool:
        """
        Validate tool arguments.
        
        Args:
            args: Tool arguments
            
        Returns:
            bool: True if arguments are valid
        """
        if not args.get('domain'):
            self.logger.error("Domain argument is required")
            return False
            
        if not is_valid_domain(args['domain']):
            self.logger.error(f"Invalid domain: {args['domain']}")
            return False
            
        return True

    def scan_target(self, domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Scan a target domain for SSL/TLS configuration.
        
        Args:
            domain: Target domain
            port: Target port (default: 443)
            
        Returns:
            Optional[Dict[str, Any]]: Scan results
        """
        try:
            # Create the scan request
            server_location = ServerNetworkLocation(domain, port)
            request = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                }
            )

            # Run the scan
            scanner = Scanner()
            scanner.queue_scan(request)
            results = [r for r in scanner.get_results()]
            
            if not results:
                self.logger.warning(f"No scan results for {domain}")
                return None
                
            scan_result = results[0]
            
            # Extract certificate info
            cert_info = None
            if scan_result.scan_commands_results.get(ScanCommand.CERTIFICATE_INFO):
                cert_info: CertificateInfoScanResult = scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
                
            findings = {
                'domain': domain,
                'port': port,
                'timestamp': datetime.now().isoformat(),
                'certificate': {
                    'subject': str(cert_info.certificate_deployments[0].received_certificate_chain[0].subject)
                    if cert_info else None,
                    'issuer': str(cert_info.certificate_deployments[0].received_certificate_chain[0].issuer)
                    if cert_info else None,
                    'not_before': cert_info.certificate_deployments[0].received_certificate_chain[0].not_valid_before.isoformat()
                    if cert_info else None,
                    'not_after': cert_info.certificate_deployments[0].received_certificate_chain[0].not_valid_after.isoformat()
                    if cert_info else None,
                },
                'protocols': {
                    'ssl2': bool(scan_result.scan_commands_results.get(ScanCommand.SSL_2_0_CIPHER_SUITES)),
                    'ssl3': bool(scan_result.scan_commands_results.get(ScanCommand.SSL_3_0_CIPHER_SUITES)),
                    'tls1_0': bool(scan_result.scan_commands_results.get(ScanCommand.TLS_1_0_CIPHER_SUITES)),
                    'tls1_1': bool(scan_result.scan_commands_results.get(ScanCommand.TLS_1_1_CIPHER_SUITES)),
                    'tls1_2': bool(scan_result.scan_commands_results.get(ScanCommand.TLS_1_2_CIPHER_SUITES)),
                    'tls1_3': bool(scan_result.scan_commands_results.get(ScanCommand.TLS_1_3_CIPHER_SUITES)),
                }
            }
            
            # Add security warnings
            warnings = []
            if findings['protocols']['ssl2']:
                warnings.append("SSLv2 is enabled (insecure)")
            if findings['protocols']['ssl3']:
                warnings.append("SSLv3 is enabled (insecure)")
            if findings['protocols']['tls1_0']:
                warnings.append("TLSv1.0 is enabled (outdated)")
            if findings['protocols']['tls1_1']:
                warnings.append("TLSv1.1 is enabled (outdated)")
                
            if warnings:
                findings['warnings'] = warnings
                
            return findings
            
        except ConnectionToServerFailed as e:
            self.logger.error(f"Connection failed to {domain}:{port} - {str(e)}")
        except Exception as e:
            self.logger.error(f"Error scanning {domain}:{port} - {str(e)}")
            
        return None

    def run(self, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run the SSL Scanner tool.
        
        Args:
            args: Tool arguments including:
                - domain: Target domain
                - subdomains: Optional list of subdomains
                
        Returns:
            List[Dict[str, Any]]: List of findings
        """
        if not self.validate_args(args):
            return []
            
        domain = args['domain']
        subdomains = args.get('subdomains', [])
        
        # Scan main domain
        result = self.scan_target(domain)
        if result:
            self.findings.append(result)
            
        # Scan subdomains if provided
        for subdomain in subdomains:
            result = self.scan_target(subdomain)
            if result:
                self.findings.append(result)
                
        return self.findings


def main():
    """Run the tool directly."""
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ssl_scanner.py <domain>")
        sys.exit(1)
        
    tool = SSLScannerTool()
    results = tool.run({'domain': sys.argv[1]})
    
    for result in results:
        print(f"\nResults for {result['domain']}:")
        print(f"Certificate Subject: {result['certificate']['subject']}")
        print(f"Certificate Issuer: {result['certificate']['issuer']}")
        print(f"Valid From: {result['certificate']['not_before']}")
        print(f"Valid Until: {result['certificate']['not_after']}")
        print("\nProtocol Support:")
        for protocol, enabled in result['protocols'].items():
            print(f"  {protocol}: {'Enabled' if enabled else 'Disabled'}")
        if 'warnings' in result:
            print("\nWarnings:")
            for warning in result['warnings']:
                print(f"  - {warning}")

if __name__ == '__main__':
    main() 