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

import argparse
import concurrent.futures
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
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class DNSProtocolFuzzer(BaseTool):
    """DNS Protocol Fuzzer for testing server robustness and finding vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="dns-protocol-fuzzer",
            description="DNS Protocol Fuzzer for testing server robustness"
        )
        self.domain = None
        self.nameserver = None
        self.timeout = 2
        
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

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        super().setup_argparse(parser)
        
        parser.add_argument('domain', help='Target domain to fuzz')
        parser.add_argument('--nameserver', help='Specific nameserver to test')
        parser.add_argument('--timeout', type=int, default=2,
                          help='Timeout for DNS queries in seconds')
        parser.add_argument('--fuzz-types', action='store_true',
                          help='Fuzz different query types')
        parser.add_argument('--fuzz-labels', action='store_true',
                          help='Fuzz label lengths')
        parser.add_argument('--fuzz-compression', action='store_true',
                          help='Fuzz compression pointers')
        parser.add_argument('--fuzz-edns', action='store_true',
                          help='Fuzz EDNS options')
        parser.add_argument('--fuzz-malformed', action='store_true',
                          help='Send malformed packets')
        parser.add_argument('--fuzz-all', action='store_true',
                          help='Run all fuzzing tests')
        parser.add_argument('--parallel', type=int, default=5,
                          help='Number of parallel fuzzing threads')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the fuzzing tests"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={"domain": args.domain}
        )
        
        try:
            self.domain = args.domain
            self.timeout = args.timeout
            
            # Get nameserver
            if args.nameserver:
                self.nameserver = args.nameserver
            else:
                try:
                    ns_records = dns.resolver.resolve(self.domain, 'NS')
                    if not ns_records:
                        result.add_error("No nameservers found for domain")
                        return result
                    
                    # Get first nameserver's IP
                    ns_name = str(ns_records[0].target).rstrip('.')
                    ns_ips = dns.resolver.resolve(ns_name, 'A')
                    self.nameserver = str(ns_ips[0])
                    
                except Exception as e:
                    result.add_error(f"Error getting nameserver: {str(e)}")
                    return result
            
            result.metadata["nameserver"] = self.nameserver
            
            # Determine which tests to run
            run_all = args.fuzz_all
            tests = {
                'types': run_all or args.fuzz_types,
                'labels': run_all or args.fuzz_labels,
                'compression': run_all or args.fuzz_compression,
                'edns': run_all or args.fuzz_edns,
                'malformed': run_all or args.fuzz_malformed
            }
            
            # Run selected tests
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
                futures = []
                
                if tests['types']:
                    futures.extend([
                        executor.submit(self._fuzz_query_type, result, qtype)
                        for qtype in self.fuzz_config['query_types']
                    ])
                
                if tests['labels']:
                    futures.extend([
                        executor.submit(self._fuzz_label_length, result, length)
                        for length in self.fuzz_config['label_lengths']
                    ])
                
                if tests['compression']:
                    futures.extend([
                        executor.submit(self._fuzz_compression, result, offset)
                        for offset in self.fuzz_config['compression_offsets']
                    ])
                
                if tests['edns']:
                    futures.extend([
                        executor.submit(self._fuzz_edns_option, result, option)
                        for option in self.fuzz_config['edns_options']
                    ])
                
                if tests['malformed']:
                    futures.extend([
                        executor.submit(self._send_malformed_packet, result, pattern)
                        for pattern in self.fuzz_config['malformed_patterns']
                    ])
                
                # Wait for all tests to complete
                concurrent.futures.wait(futures)
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during fuzzing: {str(e)}")
            return result

    def _fuzz_query_type(self, result: ToolResult, qtype: int) -> None:
        """Test server response to different query types"""
        try:
            request = dns.message.make_query(self.domain, qtype)
            response = dns.query.udp(request, self.nameserver, timeout=self.timeout)
            
            # Check for unexpected responses
            if response.rcode() not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
                result.add_finding(
                    title=f"Unexpected Response for Query Type {qtype}",
                    description=f"Server returned unexpected rcode {response.rcode()}",
                    risk_level="Medium",
                    evidence=f"Query type: {dns.rdatatype.to_text(qtype)}"
                )
            
            # Check for large responses
            if len(response.to_wire()) > 4096:
                result.add_finding(
                    title="Large Response Detected",
                    description=f"Server returned unusually large response for query type {qtype}",
                    risk_level="Medium",
                    evidence=f"Response size: {len(response.to_wire())} bytes"
                )
                
        except Exception as e:
            if "timeout" in str(e).lower():
                result.add_finding(
                    title=f"Timeout on Query Type {qtype}",
                    description="Server failed to respond within timeout period",
                    risk_level="Low",
                    evidence=str(e)
                )
            else:
                result.add_finding(
                    title=f"Error Testing Query Type {qtype}",
                    description=f"Unexpected error: {str(e)}",
                    risk_level="Info"
                )

    def _fuzz_label_length(self, result: ToolResult, length: int) -> None:
        """Test server handling of various label lengths"""
        try:
            # Create domain name with specified label length
            if length > 0:
                label = 'a' * length
                test_domain = f"{label}.{self.domain}"
            else:
                test_domain = f".{self.domain}"
            
            request = dns.message.make_query(test_domain, dns.rdatatype.A)
            response = dns.query.udp(request, self.nameserver, timeout=self.timeout)
            
            # Check for unexpected success with invalid lengths
            if length > 63 and response.rcode() == dns.rcode.NOERROR:
                result.add_finding(
                    title="Server Accepts Invalid Label Length",
                    description=f"Server accepted label length {length} (max valid is 63)",
                    risk_level="High",
                    evidence=f"Test domain: {test_domain}"
                )
                
        except Exception as e:
            if length <= 63:
                # Only report as finding if the length should have been valid
                result.add_finding(
                    title=f"Error Testing Label Length {length}",
                    description=str(e),
                    risk_level="Medium"
                )

    def _fuzz_compression(self, result: ToolResult, offset: int) -> None:
        """Test server handling of DNS message compression"""
        try:
            request = dns.message.make_query(self.domain, dns.rdatatype.A)
            wire = bytearray(request.to_wire())
            
            # Insert compression pointer at various positions
            if len(wire) > offset + 2:
                wire[offset] = 0xC0  # Compression pointer marker
                wire[offset + 1] = 0x0C  # Offset to first name
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    sock.sendto(wire, (self.nameserver, 53))
                    response, _ = sock.recvfrom(65535)
                    
                    # Check if server accepted malformed compression
                    if len(response) > 0:
                        result.add_finding(
                            title="Server Accepts Invalid Compression",
                            description=f"Server processed message with compression pointer at offset {offset}",
                            risk_level="Medium",
                            evidence=f"Response length: {len(response)} bytes"
                        )
                finally:
                    sock.close()
                    
        except Exception as e:
            if "timeout" not in str(e).lower():
                result.add_finding(
                    title=f"Error Testing Compression Offset {offset}",
                    description=str(e),
                    risk_level="Info"
                )

    def _fuzz_edns_option(self, result: ToolResult, option: Dict) -> None:
        """Test server handling of EDNS options"""
        try:
            request = dns.message.make_query(self.domain, dns.rdatatype.A)
            request.use_edns(edns=0, payload=4096, options=[dns.edns.GenericOption(option['code'], option['data'])])
            
            response = dns.query.udp(request, self.nameserver, timeout=self.timeout)
            
            # Check for unexpected responses
            if response.rcode() == dns.rcode.FORMERR:
                result.add_finding(
                    title="EDNS Option Rejected",
                    description=f"Server rejected EDNS option code {option['code']}",
                    risk_level="Info",
                    evidence=f"Option data length: {len(option['data'])} bytes"
                )
            elif len(response.to_wire()) > 4096:
                result.add_finding(
                    title="Large EDNS Response",
                    description="Server returned unusually large EDNS response",
                    risk_level="Medium",
                    evidence=f"Response size: {len(response.to_wire())} bytes"
                )
                
        except Exception as e:
            result.add_finding(
                title=f"Error Testing EDNS Option {option['code']}",
                description=str(e),
                risk_level="Info"
            )

    def _send_malformed_packet(self, result: ToolResult, pattern: bytes) -> None:
        """Test server handling of malformed packets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            try:
                # Send malformed packet
                sock.sendto(pattern, (self.nameserver, 53))
                response, _ = sock.recvfrom(65535)
                
                # Check if server responded to malformed packet
                if len(response) > 0:
                    result.add_finding(
                        title="Server Responds to Malformed Packet",
                        description="Server processed malformed DNS packet",
                        risk_level="High",
                        evidence=f"Pattern: {pattern.hex()}, Response length: {len(response)}"
                    )
            finally:
                sock.close()
                
        except Exception as e:
            if "timeout" not in str(e).lower():
                result.add_finding(
                    title="Error Testing Malformed Packet",
                    description=str(e),
                    risk_level="Info",
                    evidence=f"Pattern: {pattern.hex()}"
                )

def main():
    tool = DNSProtocolFuzzer()
    return tool.main()

if __name__ == "__main__":
    sys.exit(0 if main() == 'success' else 1) 