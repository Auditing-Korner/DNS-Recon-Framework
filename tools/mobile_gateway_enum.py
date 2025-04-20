#!/usr/bin/env python3

import argparse
import json
import logging
import sys
import os
import socket
import dns.resolver
import requests
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from scapy.all import *
    from scapy.layers.inet import IP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
import ipaddress
import struct

# Handle imports for framework integration
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

@dataclass
class GatewayResult:
    """Class to store gateway enumeration results"""
    ip_address: str
    hostname: Optional[str]
    gateway_type: str
    protocols: List[str]
    ports: List[int]
    services: Dict[str, Any]
    vulnerabilities: List[Dict]
    risk_level: str
    evidence: List[str]

    def to_dict(self) -> Dict:
        """Convert the result to a dictionary format"""
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'gateway_type': self.gateway_type,
            'protocols': self.protocols,
            'ports': self.ports,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities,
            'risk_level': self.risk_level,
            'evidence': self.evidence
        }

class MobileGatewayEnumerator(BaseTool):
    def __init__(self):
        super().__init__(
            name="mobile-gw", 
            description="Enumerate 3GPP Mobile Gateways"
        )
        self.target = None
        self.threads = 10
        self.gateway_type = None
        self.port_list = None
        self.scan_timeout = 5
        self.protocol_tests = True
        
        # Initialize results structure
        self.scan_results = {
            'scan_summary': {
                'total_ips_scanned': 0,
                'gateways_found': 0,
                'vulnerabilities_found': 0,
                'risk_summary': {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0
                },
                'timestamp': datetime.now().isoformat()
            },
            'results': [],
            'errors': [],
            'messages': []
        }
        
        # Load signature database
        self.signatures = self._load_signatures()
        
        # Common ports for mobile gateways - will be overridden by config
        self.common_ports = {
            'GGSN': [2123, 2152, 3386],  # GTP-C, GTP-U, GTP'
            'P-GW': [2123, 2152, 8080],  # GTP-C, GTP-U, REST
            'S-GW': [2123, 2152],        # GTP-C, GTP-U
            'MME': [36412, 36422],       # S1AP, X2AP
            'SGSN': [2123, 3386],        # GTP-C, GTP'
            'HSS': [3868, 3869],         # Diameter
            'PCRF': [3868, 8080]         # Diameter, REST
        }

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        super().setup_argparse(parser)
        
        parser.add_argument("target", help="Target IP, range (x.x.x.x-y.y.y.y), or CIDR")
        parser.add_argument("--gateway-type", "-g", choices=["GGSN", "P-GW", "S-GW", "MME", "SGSN", "HSS", "PCRF", "all"],
                          default="all", help="Specific gateway type to test")
        parser.add_argument("--ports", "-p", help="Comma-separated list of specific ports to scan")
        parser.add_argument("--threads", "-t", type=int, default=10, 
                          help="Number of concurrent threads")
        parser.add_argument("--timeout", type=int, default=5,
                          help="Scan timeout in seconds")
        parser.add_argument("--no-protocol-tests", action="store_true",
                          help="Skip protocol-specific tests")

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
        # Store arguments
        self.target = args.target
        self.threads = args.threads
        self.gateway_type = args.gateway_type
        self.scan_timeout = args.timeout
        self.protocol_tests = not args.no_protocol_tests
        
        # Parse ports if specified
        if args.ports:
            try:
                self.port_list = [int(p) for p in args.ports.split(',')]
            except ValueError:
                self.logger.error("Invalid port specification. Use comma-separated list of port numbers.")
                return self._create_error_result("Invalid port specification")
        
        # Load configuration if available
        self._load_config_from_framework()
        
        # Run the scan
        try:
            gateway_results = self.scan_network(self.target, self.threads)
            
            # Create tool result
            tool_result = ToolResult(
                success=True,
                tool_name=self.name,
                findings=[],
                metadata={
                    "scan_date": datetime.now().isoformat(),
                    "target": self.target,
                    "gateway_type": self.gateway_type
                }
            )
            
            # Add findings based on results
            for result in gateway_results:
                if result.gateway_type != "Unknown":
                    # Add finding for each gateway
                    tool_result.add_finding(
                        title=f"{result.gateway_type} Gateway Detected",
                        description=f"Mobile gateway detected at {result.ip_address} ({result.hostname or 'Unknown hostname'})",
                        risk_level=result.risk_level,
                        evidence="\n".join(result.evidence)
                    )
                    
                    # Add findings for each vulnerability
                    for vuln in result.vulnerabilities:
                        tool_result.add_finding(
                            title=vuln.get('name', 'Vulnerability'),
                            description=vuln.get('description', 'No description'),
                            risk_level=vuln.get('risk', 'Low'),
                            evidence=vuln.get('evidence', 'No evidence')
                        )
            
            # Update raw output
            tool_result.raw_output = self.scan_results
            
            return tool_result
        
        except Exception as e:
            self.logger.error(f"Error during execution: {str(e)}")
            return self._create_error_result(str(e))

    def _create_error_result(self, error_message: str) -> ToolResult:
        """Create an error result"""
        result = ToolResult(
            success=False,
            tool_name=self.name,
            findings=[]
        )
        result.add_error(error_message)
        return result

    def _load_config_from_framework(self):
        """Load configuration from framework config"""
        try:
            from config_manager import ConfigManager
            config = ConfigManager()
            
            # Load mobile gateway configuration
            mobile_gw_config = config.get("tools", {}).get("mobile_gw", {})
            
            # Update ports configuration if available
            if "ports" in mobile_gw_config:
                self.common_ports = mobile_gw_config["ports"]
            
            # Update scan timeout
            if "scan_timeout" in mobile_gw_config:
                self.scan_timeout = mobile_gw_config["scan_timeout"]
            
            # Update protocol tests setting
            if "protocol_tests" in mobile_gw_config:
                self.protocol_tests = mobile_gw_config["protocol_tests"]
                
            self.logger.info("Loaded configuration from framework")
            
        except ImportError:
            self.logger.warning("Could not load framework configuration, using defaults")
        except Exception as e:
            self.logger.warning(f"Error loading configuration: {str(e)}")

    def check_dependencies(self):
        """Check if all required dependencies are available"""
        if not SCAPY_AVAILABLE:
            return False, "Scapy is required for GTP packet crafting but not available"
        return True, None

    def _load_signatures(self) -> Dict:
        """Load gateway signatures and detection patterns"""
        return {
            "gateway_types": {
                "GGSN": {
                    "protocols": ["GTP", "RADIUS", "DNS"],
                    "headers": [
                        "GGSN",
                        "Gateway GPRS Support Node",
                        "3GPP-GGSN-MCC-MNC"
                    ],
                    "banners": [
                        "Cisco GGSN",
                        "Nokia GGSN",
                        "Ericsson GGSN"
                    ]
                },
                "P-GW": {
                    "protocols": ["GTP", "PMIP", "S5/S8"],
                    "headers": [
                        "P-GW",
                        "PDN Gateway",
                        "3GPP-PGW"
                    ],
                    "banners": [
                        "Cisco PGW",
                        "Nokia PGW",
                        "Ericsson PGW"
                    ]
                },
                "S-GW": {
                    "protocols": ["GTP", "S1-U", "S5/S8"],
                    "headers": [
                        "S-GW",
                        "Serving Gateway",
                        "3GPP-SGW"
                    ],
                    "banners": [
                        "Cisco SGW",
                        "Nokia SGW",
                        "Ericsson SGW"
                    ]
                },
                "MME": {
                    "protocols": ["S1-MME", "S10", "S11"],
                    "headers": [
                        "MME",
                        "Mobility Management Entity",
                        "3GPP-MME"
                    ],
                    "banners": [
                        "Cisco MME",
                        "Nokia MME",
                        "Ericsson MME"
                    ]
                }
            },
            "vulnerabilities": {
                "open_gtp": {
                    "name": "Open GTP Port",
                    "description": "GTP port accessible from external network",
                    "risk": "High",
                    "recommendation": "Restrict GTP access to trusted networks"
                },
                "weak_auth": {
                    "name": "Weak Authentication",
                    "description": "Weak or missing authentication on gateway interface",
                    "risk": "Critical",
                    "recommendation": "Implement strong authentication mechanisms"
                },
                "version_disclosure": {
                    "name": "Version Disclosure",
                    "description": "Gateway software version exposed",
                    "risk": "Medium",
                    "recommendation": "Hide version information in responses"
                }
            }
        }

    def create_gtp_echo_request(self) -> bytes:
        """Create a GTP Echo Request packet"""
        # GTP v1 Echo Request
        gtp_header = (
            b'\x32'  # Version (1) | PT (1) | Reserved | Message Type (Echo Request)
            b'\x00\x00\x00'  # Length
            b'\x00\x00\x00\x00'  # TEID
            b'\x00\x00'  # Sequence Number
            b'\x00\x00'  # NPDU Number and Next Extension Header Type
        )
        return gtp_header

    def detect_gtp_service(self, ip: str, port: int) -> Optional[Dict]:
        """Detect GTP service on specified IP and port"""
        if not self.protocol_tests:
            return None
            
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.scan_timeout)
            
            # Send GTP Echo Request
            echo_request = self.create_gtp_echo_request()
            sock.sendto(echo_request, (ip, port))
            
            # Wait for response
            try:
                data, addr = sock.recvfrom(1024)
                if data:
                    # Check if response is GTP Echo Response
                    if len(data) >= 1 and data[0] & 0xE0 == 0x20:  # GTP v1
                        return {
                            "service": "GTP",
                            "version": "1",
                            "port": port
                        }
            except socket.timeout:
                pass
            
            sock.close()
            return None
            
        except Exception as e:
            self.logger.warning(f"Error detecting GTP service on {ip}:{port}: {str(e)}")
            return None

    def detect_diameter_service(self, ip: str, port: int) -> Optional[Dict]:
        """Detect Diameter service on specified IP and port"""
        if not self.protocol_tests:
            return None
            
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            
            # Try to connect
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Send Diameter Capabilities-Exchange-Request
                cer = (
                    b'\x01\x00\x00\x00'  # Version 1, Length
                    b'\x80\x00\x01\x01'  # R=1, P=0, E=0, T=0, Code=257 (CER)
                    b'\x00\x00\x00\x00'  # Application ID
                    b'\x00\x00\x00\x00'  # Hop-by-Hop ID
                    b'\x00\x00\x00\x00'  # End-to-End ID
                )
                sock.send(cer)
                
                try:
                    data = sock.recv(1024)
                    if data and len(data) >= 4:
                        return {
                            "service": "Diameter",
                            "version": str(data[0]),
                            "port": port
                        }
                except socket.timeout:
                    pass
            
            sock.close()
            return None
            
        except Exception as e:
            self.logger.warning(f"Error detecting Diameter service on {ip}:{port}: {str(e)}")
            return None

    def scan_ports(self, ip: str) -> List[int]:
        """Scan for open mobile gateway ports"""
        open_ports = []
        
        try:
            # Determine which ports to scan
            ports_to_scan = []
            if self.port_list:
                ports_to_scan = self.port_list
            elif self.gateway_type and self.gateway_type != "all":
                ports_to_scan = self.common_ports.get(self.gateway_type, [])
            else:
                # Scan all common mobile gateway ports
                for ports in self.common_ports.values():
                    ports_to_scan.extend(ports)
                # Remove duplicates
                ports_to_scan = list(set(ports_to_scan))
            
            # Perform the scan
            for port in ports_to_scan:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.scan_timeout)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    continue
            
            return open_ports
        except Exception as e:
            self.logger.error(f'Error scanning ports: {str(e)}')
            return []

    def identify_gateway_type(self, open_ports: List[int]) -> Optional[str]:
        """Identify gateway type based on open ports"""
        # If gateway type specified, only check that type
        if self.gateway_type and self.gateway_type != "all":
            if any(port in self.common_ports.get(self.gateway_type, []) for port in open_ports):
                return self.gateway_type
            return None
        
        # Otherwise check all gateway types
        for gw_type, ports in self.common_ports.items():
            if any(port in ports for port in open_ports):
                return gw_type
        return None

    def check_vulnerabilities(self, ip: str, services: Dict[int, Dict]) -> List[Dict]:
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for open GTP ports
        gtp_ports = [2123, 2152, 3386]
        for port in gtp_ports:
            if port in services:
                vuln = self.signatures['vulnerabilities']['open_gtp'].copy()
                vuln['evidence'] = f"GTP port {port} is accessible"
                vulnerabilities.append(vuln)
        
        # Check for version disclosure
        for service_info in services.values():
            if 'banner' in service_info:
                for gw_type in self.signatures['gateway_types'].values():
                    for banner in gw_type['banners']:
                        if banner.lower() in service_info['banner'].lower():
                            vuln = self.signatures['vulnerabilities']['version_disclosure'].copy()
                            vuln['evidence'] = f"Version information disclosed: {service_info['banner']}"
                            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def analyze_gateway(self, target):
        """Analyze a potential mobile gateway"""
        try:
            self.logger.info(f'Analyzing potential mobile gateway at {target}')
            
            # Initialize gateway result
            result = GatewayResult(
                ip_address=target,
                hostname=None,
                gateway_type="Unknown",
                protocols=[],
                ports=[],
                services={},
                vulnerabilities=[],
                risk_level="Low",
                evidence=[]
            )
            
            # Check for common mobile gateway ports
            open_ports = self.scan_ports(target)
            if not open_ports:
                return None
            
            # Identify gateway type based on open ports
            gateway_type = self.identify_gateway_type(open_ports)
            if not gateway_type:
                return None
            
            result.gateway_type = gateway_type
            result.ports = open_ports
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(target)[0]
                result.hostname = hostname
            except:
                pass
            
            # Scan common gateway ports
            all_ports = set()
            for ports in self.common_ports.values():
                all_ports.update(ports)
            
            services = {}
            for port in open_ports:
                try:
                    if port in [2123, 2152, 3386]:  # GTP ports
                        service = self.detect_gtp_service(target, port)
                        if service:
                            services[port] = service
                    elif port in [3868, 3869]:  # Diameter ports
                        service = self.detect_diameter_service(target, port)
                        if service:
                            services[port] = service
                    else:
                        # Generic service detection
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.scan_timeout)
                        if sock.connect_ex((target, port)) == 0:
                            try:
                                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                                services[port] = {
                                    "service": "Unknown",
                                    "banner": banner if banner else "No banner",
                                    "port": port
                                }
                            except:
                                services[port] = {
                                    "service": "Unknown",
                                    "port": port
                                }
                        sock.close()
                except Exception as e:
                    self.logger.warning(f'Error detecting service on port {port}: {str(e)}')
            
            result.services = services
            
            # Get list of detected protocols
            protocols = list(set(
                service['service'] for service in services.values()
                if service.get('service') != 'Unknown'
            ))
            result.protocols = protocols
            
            # Check for vulnerabilities
            try:
                vulnerabilities = self.check_vulnerabilities(target, services)
                result.vulnerabilities = vulnerabilities
            except Exception as e:
                self.logger.warning(f'Error checking vulnerabilities: {str(e)}')
            
            # Determine risk level
            risk_level = "Low"
            if any(v.get('risk') == 'Critical' for v in result.vulnerabilities):
                risk_level = "Critical"
            elif any(v.get('risk') == 'High' for v in result.vulnerabilities):
                risk_level = "High"
            elif any(v.get('risk') == 'Medium' for v in result.vulnerabilities):
                risk_level = "Medium"
            result.risk_level = risk_level
            
            # Collect evidence
            evidence = []
            if result.hostname:
                evidence.append(f"Hostname: {result.hostname}")
            for port, service in result.services.items():
                evidence.append(f"Port {port}: {service.get('service', 'Unknown')}")
                if 'banner' in service:
                    evidence.append(f"Banner on port {port}: {service['banner']}")
            result.evidence = evidence
            
            # Update scan summary
            self.scan_results['scan_summary']['gateways_found'] += 1
            self.scan_results['scan_summary']['vulnerabilities_found'] += len(result.vulnerabilities)
            
            for vuln in result.vulnerabilities:
                risk_level = vuln.get('risk', 'Low')
                if risk_level in self.scan_results['scan_summary']['risk_summary']:
                    self.scan_results['scan_summary']['risk_summary'][risk_level] += 1
            
            # Add result to results list
            self.scan_results['results'].append(result.to_dict())
            
            return result
            
        except Exception as e:
            self.logger.error(f'Error analyzing gateway at {target}: {str(e)}')
            return None

    def scan_network(self, target, threads=10):
        """Scan a network range for mobile gateways"""
        try:
            # Parse target (IP, range, or CIDR)
            try:
                if '-' in target:
                    start_ip, end_ip = target.split('-')
                    targets = self._ip_range(start_ip, end_ip)
                elif '/' in target:
                    targets = [str(ip) for ip in ipaddress.ip_network(target)]
                else:
                    targets = [target]
            except Exception as e:
                self.logger.error(f'Error parsing target: {str(e)}')
                return []

            self.logger.info(f'Scanning {len(targets)} IP addresses for mobile gateways')
            
            results = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_ip = {executor.submit(self.analyze_gateway, ip): ip for ip in targets}
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        self.logger.error(f'Error scanning {ip}: {str(e)}')
            
            return results
            
        except Exception as e:
            self.logger.error(f'Error during network scan: {str(e)}')
            return []

    def _ip_range(self, start_ip, end_ip):
        """Generate a list of IPs from a range"""
        start = struct.unpack('>I', socket.inet_aton(start_ip))[0]
        end = struct.unpack('>I', socket.inet_aton(end_ip))[0]
        return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end + 1)]

def main():
    tool = MobileGatewayEnumerator()
    return tool.main()

if __name__ == "__main__":
    main() 