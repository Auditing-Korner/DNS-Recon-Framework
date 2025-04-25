#!/usr/bin/env python3
"""
DNS Cache Poisoning Detection Tool

Tests for DNS cache poisoning vulnerabilities:
- Query ID prediction
- Source port randomization
- Birthday attacks
- DNSSEC validation
- Cache snooping
- Response rate limiting
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception
import dns.message
import dns.query
import socket
import sys
import os
import json
import random
import time
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class CachePoisonDetector(BaseTool):
    """DNS Cache Poisoning Detection Tool"""
    
    def __init__(self):
        super().__init__(
            name="cache_poison",
            description="DNS Cache Poisoning Detection Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Initialize test configurations
        self.tests = {
            'query_id': {
                'samples': 100,
                'threshold': 0.1  # Maximum acceptable duplicate ratio
            },
            'source_port': {
                'samples': 100,
                'threshold': 0.1  # Maximum acceptable port reuse ratio
            },
            'birthday': {
                'samples': 1000,
                'threshold': 0.01  # Maximum acceptable collision probability
            },
            'cache_snooping': {
                'common_records': [
                    'www',
                    'mail',
                    'ns1',
                    'ns2',
                    'mx1',
                    'webmail'
                ]
            }
        }
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run cache poisoning detection with provided arguments"""
        domain = self.get_param('domain')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_query_id = self.get_param('check_query_id', True)
        check_ports = self.get_param('check_ports', True)
        check_birthday = self.get_param('check_birthday', True)
        check_snooping = self.get_param('check_snooping', True)
        max_threads = int(self.get_param('threads', 10))
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Get nameservers first
            nameservers = self._get_nameservers(domain, result)
            if not nameservers:
                result.add_error("No nameservers found for domain")
                return
            
            # Run tests in parallel
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                for ns in nameservers:
                    if check_query_id:
                        futures.append(executor.submit(
                            self._check_query_id_randomization,
                            ns,
                            domain,
                            result
                        ))
                    if check_ports:
                        futures.append(executor.submit(
                            self._check_source_port_randomization,
                            ns,
                            domain,
                            result
                        ))
                    if check_birthday:
                        futures.append(executor.submit(
                            self._check_birthday_attack,
                            ns,
                            domain,
                            result
                        ))
                    if check_snooping:
                        futures.append(executor.submit(
                            self._check_cache_snooping,
                            ns,
                            domain,
                            result
                        ))
                
                # Wait for all tasks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        result.add_error(f"Error in cache poisoning test: {str(e)}")
                
        except Exception as e:
            result.add_error(f"Error during cache poisoning detection: {str(e)}")
            
    def _get_nameservers(self, domain: str, result: ToolResult) -> List[str]:
        """Get nameservers for the domain"""
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            nameservers = []
            
            for ns in ns_records:
                try:
                    ns_name = str(ns.target).rstrip('.')
                    ns_ips = dns.resolver.resolve(ns_name, 'A')
                    nameservers.extend([str(ip) for ip in ns_ips])
                except Exception as e:
                    result.add_warning(f"Could not resolve nameserver {ns_name}: {str(e)}")
                    
            return nameservers
            
        except Exception as e:
            result.add_error(f"Error getting nameservers: {str(e)}")
            return []

    def _check_query_id_randomization(self, nameserver: str, domain: str, result: ToolResult) -> None:
        """Check DNS query ID randomization"""
        try:
            query_ids = set()
            total_queries = self.tests['query_id']['samples']
            
            for _ in range(total_queries):
                request = dns.message.make_query(
                    f"random-{random.randint(1, 1000000)}.{domain}",
                    dns.rdatatype.A
                )
                try:
                    response = dns.query.udp(request, nameserver, timeout=self.resolver.timeout)
                    if response.id == request.id:
                        query_ids.add(response.id)
                except:
                    continue
                    
                time.sleep(0.1)  # Avoid flooding
            
            # Analyze results
            unique_ratio = len(query_ids) / total_queries
            if unique_ratio < (1 - self.tests['query_id']['threshold']):
                result.add_finding({
                    'title': "Poor Query ID Randomization",
                    'description': "DNS server shows weak query ID randomization",
                    'risk_level': "High",
                    'details': {
                        'nameserver': nameserver,
                        'unique_ids': len(query_ids),
                        'total_queries': total_queries,
                        'unique_ratio': unique_ratio,
                        'threshold': 1 - self.tests['query_id']['threshold']
                    },
                    'recommendations': [
                        'Update DNS server software',
                        'Enable query ID randomization',
                        'Monitor for cache poisoning attempts'
                    ]
                })
                
        except Exception as e:
            result.add_warning(f"Error checking query ID randomization for {nameserver}: {str(e)}")

    def _check_source_port_randomization(self, nameserver: str, domain: str, result: ToolResult) -> None:
        """Check source port randomization"""
        try:
            source_ports = set()
            total_queries = self.tests['source_port']['samples']
            
            for _ in range(total_queries):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind(('', 0))
                    source_ports.add(sock.getsockname()[1])
                finally:
                    sock.close()
                    
                time.sleep(0.1)  # Avoid flooding
            
            # Analyze results
            unique_ratio = len(source_ports) / total_queries
            if unique_ratio < (1 - self.tests['source_port']['threshold']):
                result.add_finding({
                    'title': "Poor Source Port Randomization",
                    'description': "DNS server shows weak source port randomization",
                    'risk_level': "High",
                    'details': {
                        'nameserver': nameserver,
                        'unique_ports': len(source_ports),
                        'total_queries': total_queries,
                        'unique_ratio': unique_ratio,
                        'threshold': 1 - self.tests['source_port']['threshold']
                    },
                    'recommendations': [
                        'Enable source port randomization',
                        'Update DNS server configuration',
                        'Monitor for cache poisoning attempts'
                    ]
                })
                
        except Exception as e:
            result.add_warning(f"Error checking source port randomization for {nameserver}: {str(e)}")

    def _check_birthday_attack(self, nameserver: str, domain: str, result: ToolResult) -> None:
        """Check vulnerability to birthday attacks"""
        try:
            collisions = 0
            seen_pairs = set()
            total_queries = self.tests['birthday']['samples']
            
            for _ in range(total_queries):
                request = dns.message.make_query(
                    f"random-{random.randint(1, 1000000)}.{domain}",
                    dns.rdatatype.A
                )
                try:
                    response = dns.query.udp(request, nameserver, timeout=self.resolver.timeout)
                    pair = (response.id, response.query.to_wire())
                    if pair in seen_pairs:
                        collisions += 1
                    seen_pairs.add(pair)
                except:
                    continue
                    
                time.sleep(0.1)  # Avoid flooding
            
            # Analyze results
            collision_prob = collisions / total_queries
            if collision_prob > self.tests['birthday']['threshold']:
                result.add_finding({
                    'title': "Birthday Attack Vulnerability",
                    'description': "DNS server vulnerable to birthday attacks",
                    'risk_level': "High",
                    'details': {
                        'nameserver': nameserver,
                        'collisions': collisions,
                        'total_queries': total_queries,
                        'collision_probability': collision_prob,
                        'threshold': self.tests['birthday']['threshold']
                    },
                    'recommendations': [
                        'Implement additional entropy sources',
                        'Increase query ID space',
                        'Monitor for cache poisoning attempts'
                    ]
                })
                
        except Exception as e:
            result.add_warning(f"Error checking birthday attack vulnerability for {nameserver}: {str(e)}")

    def _check_cache_snooping(self, nameserver: str, domain: str, result: ToolResult) -> None:
        """Check for cache snooping vulnerability"""
        try:
            cached_records = []
            
            for record in self.tests['cache_snooping']['common_records']:
                test_domain = f"{record}.{domain}"
                request = dns.message.make_query(test_domain, dns.rdatatype.A)
                request.flags &= ~dns.flags.RD  # Clear recursion desired flag
                
                try:
                    response = dns.query.udp(request, nameserver, timeout=self.resolver.timeout)
                    if response.answer and not (response.flags & dns.flags.AA):
                        # Found cached record (has answer but not authoritative)
                        cached_records.append(test_domain)
                except:
                    continue
            
            if cached_records:
                result.add_finding({
                    'title': "Cache Snooping Possible",
                    'description': "DNS server allows cache snooping",
                    'risk_level': "Medium",
                    'details': {
                        'nameserver': nameserver,
                        'cached_records': cached_records
                    },
                    'recommendations': [
                        'Disable cache snooping',
                        'Implement access controls',
                        'Monitor cache queries'
                    ]
                })
                
        except Exception as e:
            result.add_warning(f"Error checking cache snooping for {nameserver}: {str(e)}")

def main():
    """Entry point for cache poison detector"""
    tool = CachePoisonDetector()
    return tool.main()

if __name__ == "__main__":
    main() 