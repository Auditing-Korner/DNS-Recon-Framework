#!/usr/bin/env python3
"""
Mobile Gateway Enumeration Tool

Enumerates and tests 3GPP mobile network gateways:
- GGSN (Gateway GPRS Support Node)
- P-GW (PDN Gateway)
- S-GW (Serving Gateway)
- MME (Mobility Management Entity)
- SGSN (Serving GPRS Support Node)
- HSS (Home Subscriber Server)
- PCRF (Policy and Charging Rules Function)
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import socket
import sys
import os
import json
import struct
import random
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class MobileGatewayEnumerator(BaseTool):
    """Mobile Gateway Enumeration Tool"""
    
    def __init__(self):
        super().__init__(
            name="mobile_gw",
            description="Mobile Gateway Enumeration Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize gateway configurations
        self.gateways = {
            'GGSN': {
                'ports': [2123, 2152, 3386],  # GTP-C, GTP-U, GTP'
                'protocols': ['udp'],
                'patterns': [
                    'ggsn',
                    'gprs',
                    'gtp'
                ]
            },
            'P-GW': {
                'ports': [2123, 2152, 8805],  # GTP-C, GTP-U, Diameter
                'protocols': ['udp', 'tcp'],
                'patterns': [
                    'pgw',
                    'pdn',
                    'gtp'
                ]
            },
            'S-GW': {
                'ports': [2123, 2152, 8805],  # GTP-C, GTP-U, Diameter
                'protocols': ['udp', 'tcp'],
                'patterns': [
                    'sgw',
                    'serving',
                    'gtp'
                ]
            },
            'MME': {
                'ports': [36412, 36422, 8805],  # S1AP, X2AP, Diameter
                'protocols': ['sctp', 'tcp'],
                'patterns': [
                    'mme',
                    'mobility',
                    'epc'
                ]
            },
            'SGSN': {
                'ports': [2123, 2152, 3386],  # GTP-C, GTP-U, GTP'
                'protocols': ['udp'],
                'patterns': [
                    'sgsn',
                    'gprs',
                    'gtp'
                ]
            },
            'HSS': {
                'ports': [3868, 3869, 3870],  # Diameter
                'protocols': ['tcp', 'sctp'],
                'patterns': [
                    'hss',
                    'subscriber',
                    'diameter'
                ]
            },
            'PCRF': {
                'ports': [3868, 3869, 3870],  # Diameter
                'protocols': ['tcp', 'sctp'],
                'patterns': [
                    'pcrf',
                    'policy',
                    'diameter'
                ]
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run mobile gateway enumeration with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        gateway_types = self.get_param('gateway_types', 'all').split(',')
        check_protocols = self.get_param('check_protocols', True)
        max_threads = int(self.get_param('threads', 10))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Get subdomains first
            subdomains = self._enumerate_subdomains(domain, result)
            if not subdomains:
                result.add_warning("No subdomains found to check")
                return
            
            # Check each gateway type if specified
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                for gateway_type, config in self.gateways.items():
                    if 'all' in gateway_types or gateway_type.lower() in gateway_types:
                        # Submit tasks for each subdomain
                        for subdomain in subdomains:
                            futures.append(executor.submit(
                                self._check_gateway,
                                subdomain,
                                gateway_type,
                                config,
                                check_protocols,
                                result
                            ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in gateway check: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during gateway enumeration: {str(e)}")
            
    def _enumerate_subdomains(self, domain: str, result: ToolResult) -> Set[str]:
        """Enumerate subdomains using various methods"""
        subdomains = set()
        
        try:
            # Try zone transfer first
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    try:
                        xfr = dns.query.xfr(str(ns), domain)
                        zone = dns.zone.from_xfr(xfr)
                        for name, node in zone.nodes.items():
                            subdomain = str(name)
                            if subdomain != '@':
                                subdomains.add(f"{subdomain}.{domain}")
                    except:
                        continue
            except:
                pass
            
            # Try common record types
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if record_type == 'MX':
                            subdomains.add(str(rdata.exchange).rstrip('.'))
                        elif record_type == 'CNAME':
                            subdomains.add(str(rdata.target).rstrip('.'))
                        else:
                            subdomains.add(str(rdata))
                except:
                    continue
                    
            # Add common mobile gateway subdomains
            common_subs = [
                'ggsn', 'pgw', 'sgw', 'mme', 'sgsn', 'hss', 'pcrf',
                'epc', 'core', 'mobile', 'cellular', '3gpp', 'lte'
            ]
            
            for sub in common_subs:
                subdomains.add(f"{sub}.{domain}")
                    
        except Exception as e:
            result.add_warning(f"Error enumerating subdomains: {str(e)}")
            
        return subdomains

    def _check_gateway(self, subdomain: str, gateway_type: str, config: Dict,
                      check_protocols: bool, result: ToolResult) -> None:
        """Check subdomain for mobile gateway presence"""
        try:
            # Check DNS patterns first
            found_patterns = []
            subdomain_parts = subdomain.lower().split('.')
            
            for pattern in config['patterns']:
                if any(pattern in part for part in subdomain_parts):
                    found_patterns.append(pattern)
            
            if found_patterns:
                # Get IP addresses
                try:
                    ip_addresses = []
                    for record_type in ['A', 'AAAA']:
                        try:
                            answers = dns.resolver.resolve(subdomain, record_type)
                            ip_addresses.extend([str(rr) for rr in answers])
                        except:
                            continue
                            
                    if ip_addresses:
                        finding = {
                            'title': f"Potential {gateway_type} Gateway",
                            'description': f"Found {gateway_type} patterns on {subdomain}",
                            'risk_level': "Medium",
                            'details': {
                                'subdomain': subdomain,
                                'gateway_type': gateway_type,
                                'patterns': found_patterns,
                                'ip_addresses': ip_addresses
                            },
                            'recommendations': [
                                'Verify gateway exposure',
                                'Review firewall rules',
                                'Implement access controls'
                            ]
                        }
                        
                        # Check protocols if enabled
                        if check_protocols:
                            open_ports = self._check_ports(ip_addresses[0], config['ports'], config['protocols'])
                            if open_ports:
                                finding['risk_level'] = "High"
                                finding['details']['open_ports'] = open_ports
                                finding['recommendations'].extend([
                                    'Restrict protocol access',
                                    'Configure protocol security',
                                    'Monitor gateway traffic'
                                ])
                                
                        result.add_finding(finding)
                except:
                    pass
                    
        except Exception as e:
            result.add_warning(f"Error checking gateway {gateway_type} for {subdomain}: {str(e)}")

    def _check_ports(self, ip: str, ports: List[int], protocols: List[str]) -> Dict[str, List[int]]:
        """Check for open ports and protocols"""
        open_ports = {proto: [] for proto in protocols}
        
        for protocol in protocols:
            for port in ports:
                try:
                    if protocol == 'udp':
                        # Send UDP probe
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(self.resolver.timeout)
                        
                        # Send GTP echo request if GTP port
                        if port in [2123, 2152]:
                            # GTP header: version(3), msg_type(1), length(2), teid(4)
                            gtp_echo = struct.pack('!BBHL', 0x32, 1, 4, 0)
                            sock.sendto(gtp_echo, (ip, port))
                        else:
                            sock.sendto(b'\x00', (ip, port))
                            
                        try:
                            sock.recvfrom(1024)
                            open_ports['udp'].append(port)
                        except:
                            pass
                            
                    elif protocol == 'tcp':
                        # Try TCP connection
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.resolver.timeout)
                        
                        if sock.connect_ex((ip, port)) == 0:
                            open_ports['tcp'].append(port)
                            
                    elif protocol == 'sctp':
                        # Try SCTP connection if available
                        try:
                            import sctp
                            sock = sctp.sctpsocket_tcp(socket.AF_INET)
                            sock.settimeout(self.resolver.timeout)
                            
                            if sock.connect_ex((ip, port)) == 0:
                                open_ports['sctp'].append(port)
                        except ImportError:
                            pass
                            
                finally:
                    sock.close()
                    
        return {k: v for k, v in open_ports.items() if v}

def main():
    """Entry point for mobile gateway enumerator"""
    tool = MobileGatewayEnumerator()
    return tool.main()

if __name__ == "__main__":
    main() 