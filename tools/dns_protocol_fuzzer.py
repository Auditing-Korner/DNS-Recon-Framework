#!/usr/bin/env python3
"""
DNS Protocol Fuzzer Tool

Tests DNS servers for vulnerabilities by sending malformed and unexpected queries:
- Malformed packet fuzzing
- Query type fuzzing
- Label length fuzzing
- Compression pointer fuzzing
- EDNS0 option fuzzing
- TCP/UDP protocol fuzzing
"""

import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.name
import dns.query
import dns.exception
import dns.flags
import socket
import sys
import os
import random
import time
import json
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class DNSProtocolFuzzer(BaseTool):
    """DNS Protocol Fuzzer for testing server robustness and finding vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="dns_protocol_fuzzer",
            description="DNS Protocol Fuzzer for testing server robustness"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize fuzzing configurations
        self.fuzz_config = {
            'query_types': [
                dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.MX,
                dns.rdatatype.TXT, dns.rdatatype.SOA, dns.rdatatype.NS,
                dns.rdatatype.PTR, dns.rdatatype.CNAME, dns.rdatatype.SRV,
                dns.rdatatype.DNSKEY, dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                dns.rdatatype.NSEC3, dns.rdatatype.DS, dns.rdatatype.AXFR,
                dns.rdatatype.ANY
            ],
            'label_lengths': [0, 1, 63, 64, 65, 255, 256],  # Test boundary conditions
            'compression_offsets': [0, 12, 4096, 65535],  # Test compression pointer values
            'edns_options': [
                {'code': 0, 'data': b''},  # Empty option
                {'code': 65535, 'data': b'\x00' * 4096},  # Large option
                {'code': 65280, 'data': b'\xff' * 100}  # Custom option
            ],
            'malformed_patterns': [
                b'\x00' * 12,  # All zeros header
                b'\xff' * 12,  # All ones header
                b'\x80' * 12,  # High bits set
                b'\x7f' * 12   # Low bits set
            ]
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run DNS protocol fuzzing with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        fuzz_types = self.get_param('fuzz_types', 'all').split(',')
        max_tests = int(self.get_param('max_tests', 100))
        nameserver = self.get_param('nameserver')
        parallel = int(self.get_param('parallel', 5))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Get nameserver if not provided
            if not nameserver:
                try:
                    ns_records = dns.resolver.resolve(domain, 'NS')
                    if not ns_records:
                        result.add_error("No nameservers found for domain")
                        return
                    
                    # Get first nameserver's IP
                    ns_name = str(ns_records[0].target).rstrip('.')
                    ns_ips = dns.resolver.resolve(ns_name, 'A')
                    nameserver = str(ns_ips[0])
                    self.resolver.nameservers = [nameserver]
                    
                except Exception as e:
                    result.add_error(f"Error getting nameserver: {str(e)}")
                    return
            
            # Run fuzzing tests based on selected types
            tests_run = 0
            
            # Query type fuzzing
            if 'all' in fuzz_types or 'query' in fuzz_types:
                for qtype in self.fuzz_config['query_types']:
                    if tests_run >= max_tests:
                        break
                    self._fuzz_query_type(domain, qtype, result)
                    tests_run += 1
            
            # Label length fuzzing
            if 'all' in fuzz_types or 'label' in fuzz_types:
                for length in self.fuzz_config['label_lengths']:
                    if tests_run >= max_tests:
                        break
                    self._fuzz_label_length(domain, length, result)
                    tests_run += 1
            
            # Compression pointer fuzzing
            if 'all' in fuzz_types or 'compression' in fuzz_types:
                for offset in self.fuzz_config['compression_offsets']:
                    if tests_run >= max_tests:
                        break
                    self._fuzz_compression(domain, offset, result)
                    tests_run += 1
            
            # EDNS option fuzzing
            if 'all' in fuzz_types or 'edns' in fuzz_types:
                for option in self.fuzz_config['edns_options']:
                    if tests_run >= max_tests:
                        break
                    self._fuzz_edns_option(domain, option, result)
                    tests_run += 1
            
            # Malformed packet fuzzing
            if 'all' in fuzz_types or 'malformed' in fuzz_types:
                for pattern in self.fuzz_config['malformed_patterns']:
                    if tests_run >= max_tests:
                        break
                    self._send_malformed_packet(domain, pattern, result)
                    tests_run += 1
                    
        except Exception as e:
            result.add_error(f"Error during protocol fuzzing: {str(e)}")
            
    def _fuzz_query_type(self, domain: str, qtype: int, result: ToolResult) -> None:
        """Test server response to different query types"""
        try:
            request = dns.message.make_query(domain, qtype)
            response = dns.query.udp(request, self.resolver.nameservers[0], timeout=self.resolver.timeout)
            
            # Check for unexpected responses
            if response.rcode() not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
                result.add_finding({
                    'title': f'Unexpected Response for Query Type {qtype}',
                    'description': f'Server returned unexpected rcode {response.rcode()}',
                    'risk_level': 'Medium',
                    'details': {
                        'domain': domain,
                        'query_type': dns.rdatatype.to_text(qtype),
                        'response_code': dns.rcode.to_text(response.rcode())
                    },
                    'recommendations': [
                        'Review DNS server configuration',
                        'Verify query type handling'
                    ]
                })
            
            # Check for large responses
            if len(response.to_wire()) > 4096:
                result.add_finding({
                    'title': 'Large Response Detected',
                    'description': f'Server returned unusually large response for query type {qtype}',
                    'risk_level': 'Medium',
                    'details': {
                        'domain': domain,
                        'query_type': dns.rdatatype.to_text(qtype),
                        'response_size': len(response.to_wire())
                    },
                    'recommendations': [
                        'Review response size limits',
                        'Implement response size controls'
                    ]
                })
                
        except Exception as e:
            if "timeout" in str(e).lower():
                result.add_finding({
                    'title': f'Timeout on Query Type {qtype}',
                    'description': 'Server failed to respond within timeout period',
                    'risk_level': 'Low',
                    'details': {
                        'domain': domain,
                        'query_type': dns.rdatatype.to_text(qtype),
                        'error': str(e)
                    }
                })
            else:
                result.add_finding({
                    'title': f'Error Testing Query Type {qtype}',
                    'description': f'Unexpected error: {str(e)}',
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'query_type': dns.rdatatype.to_text(qtype)
                    }
                })

    def _fuzz_label_length(self, domain: str, length: int, result: ToolResult) -> None:
        """Test server handling of various label lengths"""
        try:
            # Create domain name with specified label length
            if length > 0:
                label = 'a' * length
                test_domain = f"{label}.{domain}"
            else:
                test_domain = f".{domain}"
            
            request = dns.message.make_query(test_domain, dns.rdatatype.A)
            response = dns.query.udp(request, self.resolver.nameservers[0], timeout=self.resolver.timeout)
            
            # Check for unexpected success with invalid lengths
            if length > 63 and response.rcode() == dns.rcode.NOERROR:
                result.add_finding({
                    'title': 'Server Accepts Invalid Label Length',
                    'description': f'Server accepted label length {length} (max valid is 63)',
                    'risk_level': 'High',
                    'details': {
                        'domain': domain,
                        'test_domain': test_domain,
                        'label_length': length
                    },
                    'recommendations': [
                        'Implement proper label length validation',
                        'Follow DNS protocol specifications'
                    ]
                })
                
        except Exception as e:
            if length <= 63:
                # Only report as finding if the length should have been valid
                result.add_finding({
                    'title': f'Error Testing Label Length {length}',
                    'description': str(e),
                    'risk_level': 'Medium',
                    'details': {
                        'domain': domain,
                        'label_length': length
                    }
                })

    def _fuzz_compression(self, domain: str, offset: int, result: ToolResult) -> None:
        """Test server handling of DNS message compression"""
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A)
            wire = bytearray(request.to_wire())
            
            # Insert compression pointer at various positions
            if len(wire) > offset + 2:
                wire[offset] = 0xC0  # Compression pointer marker
                wire[offset + 1] = 0x0C  # Offset to first name
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.resolver.timeout)
                    sock.sendto(wire, (self.resolver.nameservers[0], 53))
                    response, _ = sock.recvfrom(65535)
                    
                    # Check if server accepted malformed compression
                    if len(response) > 0:
                        result.add_finding({
                            'title': 'Server Accepts Invalid Compression',
                            'description': f'Server processed message with compression pointer at offset {offset}',
                            'risk_level': 'Medium',
                            'details': {
                                'domain': domain,
                                'offset': offset,
                                'response_size': len(response)
                            },
                            'recommendations': [
                                'Implement proper compression pointer validation',
                                'Verify DNS message parsing'
                            ]
                        })
                finally:
                    sock.close()
                    
        except Exception as e:
            if "timeout" not in str(e).lower():
                result.add_finding({
                    'title': f'Error Testing Compression Offset {offset}',
                    'description': str(e),
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'offset': offset
                    }
                })

    def _fuzz_edns_option(self, domain: str, option: Dict, result: ToolResult) -> None:
        """Test server handling of EDNS options"""
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A)
            request.use_edns(edns=0, payload=4096, options=[dns.edns.GenericOption(option['code'], option['data'])])
            
            response = dns.query.udp(request, self.resolver.nameservers[0], timeout=self.resolver.timeout)
            
            # Check for unexpected responses
            if response.rcode() == dns.rcode.FORMERR:
                result.add_finding({
                    'title': 'EDNS Option Rejected',
                    'description': f'Server rejected EDNS option code {option["code"]}',
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'option_code': option['code'],
                        'data_length': len(option['data'])
                    }
                })
            elif len(response.to_wire()) > 4096:
                result.add_finding({
                    'title': 'Large EDNS Response',
                    'description': 'Server returned unusually large EDNS response',
                    'risk_level': 'Medium',
                    'details': {
                        'domain': domain,
                        'option_code': option['code'],
                        'response_size': len(response.to_wire())
                    },
                    'recommendations': [
                        'Review EDNS response size limits',
                        'Implement EDNS size controls'
                    ]
                })
                
        except Exception as e:
            result.add_finding({
                'title': f'Error Testing EDNS Option {option["code"]}',
                'description': str(e),
                'risk_level': 'Info',
                'details': {
                    'domain': domain,
                    'option_code': option['code']
                }
            })

    def _send_malformed_packet(self, domain: str, pattern: bytes, result: ToolResult) -> None:
        """Test server handling of malformed packets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.resolver.timeout)
            
            try:
                # Send malformed packet
                sock.sendto(pattern, (self.resolver.nameservers[0], 53))
                response, _ = sock.recvfrom(65535)
                
                # Check if server responded to malformed packet
                if len(response) > 0:
                    result.add_finding({
                        'title': 'Server Responds to Malformed Packet',
                        'description': 'Server processed malformed DNS packet',
                        'risk_level': 'High',
                        'details': {
                            'domain': domain,
                            'pattern': pattern.hex(),
                            'response_size': len(response)
                        },
                        'recommendations': [
                            'Implement strict packet validation',
                            'Drop malformed packets',
                            'Review DNS server security settings'
                        ]
                    })
            finally:
                sock.close()
                
        except Exception as e:
            if "timeout" not in str(e).lower():
                result.add_finding({
                    'title': 'Error Testing Malformed Packet',
                    'description': str(e),
                    'risk_level': 'Info',
                    'details': {
                        'domain': domain,
                        'pattern': pattern.hex()
                    }
                })

def main():
    """Entry point for DNS protocol fuzzer"""
    tool = DNSProtocolFuzzer()
    return tool.main()

if __name__ == "__main__":
    main() 