#!/usr/bin/env python3

import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
import hashlib
import base64
import logging
import concurrent.futures
from typing import List, Dict, Optional, Set, Tuple
import yaml
import os
import sys
import argparse
from pathlib import Path

# Handle imports for framework integration
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class DNSZoneWalker(BaseTool):
    """DNS Zone Walking tool for analyzing NSEC/NSEC3 records and performing zone enumeration."""
    
    def __init__(self):
        """Initialize the DNS Zone Walker."""
        super().__init__("zone_walker", "DNSSEC Zone Walking and NSEC/NSEC3 Analysis")
        self.known_names: Set[str] = set()
        self.nsec3_salt = None
        self.nsec3_iterations = 0
        self.resolver = dns.resolver.Resolver()
        
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool."""
        super().setup_argparse(parser)
        
        parser.add_argument('domain', help='Target domain to walk')
        parser.add_argument('--no-nsec', action='store_true',
                          help='Disable NSEC walking')
        parser.add_argument('--no-nsec3', action='store_true',
                          help='Disable NSEC3 walking')
        parser.add_argument('--no-zone-transfer', action='store_true',
                          help='Disable zone transfer attempts')
        parser.add_argument('--wordlist',
                          help='Wordlist for NSEC3 hash cracking')
        parser.add_argument('--threads', type=int, default=10,
                          help='Number of threads for parallel operations')
        parser.add_argument('--timeout', type=int, default=5,
                          help='Timeout for DNS queries in seconds')
        
    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if required dependencies are available."""
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            return True, None
        except ImportError:
            return False, "Required package 'dnspython' is not installed"

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the zone walking analysis."""
        tool_result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={"domain": args.domain}
        )

        try:
            # Load configuration
            self._load_config()
            
            # Set up tool parameters
            self.domain = args.domain
            self.threads = args.threads
            self.timeout = args.timeout
            self.resolver.timeout = args.timeout
            
            # Run the zone walking
            results = self.walk_zone(
                args.domain,
                enable_nsec=not args.no_nsec,
                enable_nsec3=not args.no_nsec3,
                enable_zone_transfer=not args.no_zone_transfer,
                wordlist=args.wordlist
            )
            
            # Process results
            if results.get('zone_transfer'):
                if results['zone_transfer']['success']:
                    tool_result.add_finding(
                        "Zone Transfer Successful",
                        "high",
                        "Zone transfer was successful, exposing zone data",
                        {"records": results['zone_transfer']['records']}
                    )
                    
            if results.get('nsec_records'):
                tool_result.add_finding(
                    "NSEC Records Found",
                    "medium",
                    f"Found {len(results['nsec_records'])} NSEC records",
                    {"records": results['nsec_records']}
                )
                
            if results.get('nsec3_records'):
                tool_result.add_finding(
                    "NSEC3 Records Found",
                    "medium",
                    f"Found {len(results['nsec3_records'])} NSEC3 records",
                    {"records": results['nsec3_records']}
                )
                
            if results.get('errors'):
                for error in results['errors']:
                    tool_result.add_error(error)
                    
            return tool_result

        except Exception as e:
            tool_result.success = False
            tool_result.add_error(f"Error during zone walking: {str(e)}")
            return tool_result

    def _load_config(self) -> None:
        """Load configuration from framework config."""
        try:
            with open("config.yaml", 'r') as f:
                config = yaml.safe_load(f)
            self.config = config.get('tools', {}).get('zone_walker', {})
        except Exception as e:
            self.logger.warning(f"Error loading config: {e}")
            self.config = {}

    def walk_zone(self, domain: str, enable_nsec: bool = True,
                 enable_nsec3: bool = True, enable_zone_transfer: bool = True,
                 wordlist: Optional[str] = None) -> Dict:
        """Main method to walk a DNS zone."""
        results = {
            'domain': domain,
            'nsec_records': [],
            'nsec3_records': [],
            'zone_transfer': None,
            'discovered_records': [],
            'errors': []
        }
        
        try:
            # Check DNSSEC status
            self._check_dnssec(domain)
            
            # Attempt zone transfers if enabled
            if enable_zone_transfer:
                results['zone_transfer'] = self._attempt_zone_transfer(domain)
            
            # Walk NSEC records if enabled
            if enable_nsec:
                results['nsec_records'] = self._walk_nsec(domain)
                
            # Walk NSEC3 records if enabled
            if enable_nsec3:
                results['nsec3_records'] = self._walk_nsec3(domain, wordlist)
                
            # Analyze the chain
            self._verify_chain(results)
                
        except Exception as e:
            results['errors'].append(str(e))
            self.logger.error(f"Error walking zone {domain}: {str(e)}")
            
        return results

    def _check_dnssec(self, domain: str) -> bool:
        """Check if domain has DNSSEC enabled."""
        try:
            answer = self.resolver.resolve(domain, 'DNSKEY')
            self.logger.info(f"DNSSEC is enabled for {domain}")
            return True
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No DNSKEY records found for {domain}")
            return False
        except Exception as e:
            self.logger.error(f"Error checking DNSSEC: {str(e)}")
            return False

    def _attempt_zone_transfer(self, domain: str) -> Dict:
        """Attempt zone transfer using AXFR/IXFR."""
        results = {'success': False, 'records': [], 'error': None}
        
        try:
            nameservers = self.resolver.resolve(domain, 'NS')
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    results['success'] = True
                    results['records'] = [str(name) + ' ' + str(node.rdtype) 
                                       for name, node in zone.nodes.items()]
                    break
                except Exception as e:
                    continue
        except Exception as e:
            results['error'] = str(e)
            
        return results

    def _walk_nsec(self, domain: str) -> List[Dict]:
        """Walk NSEC records to enumerate zone."""
        nsec_records = []
        current = domain
        
        try:
            while True:
                query = dns.message.make_query(current, dns.rdatatype.NSEC,
                                             want_dnssec=True)
                response = dns.query.udp(query, self.resolver.nameservers[0])
                
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.NSEC:
                        nsec_record = {
                            'owner': str(rrset.name),
                            'next': str(rrset[0].next),
                            'types': [dns.rdatatype.to_text(rtype) 
                                    for rtype in rrset[0].windows]
                        }
                        nsec_records.append(nsec_record)
                        
                        if str(rrset[0].next) <= current:
                            return nsec_records
                            
                        current = str(rrset[0].next)
                        break
                        
        except Exception as e:
            self.logger.error(f"Error during NSEC walk: {str(e)}")
            
        return nsec_records

    def _walk_nsec3(self, domain: str, wordlist: Optional[str] = None) -> List[Dict]:
        """Walk NSEC3 records to enumerate zone."""
        nsec3_records = []
        
        try:
            # Get NSEC3PARAM first
            query = dns.message.make_query(domain, dns.rdatatype.NSEC3PARAM,
                                         want_dnssec=True)
            response = dns.query.udp(query, self.resolver.nameservers[0])
            
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.NSEC3PARAM:
                    self.nsec3_salt = rrset[0].salt.hex()
                    self.nsec3_iterations = rrset[0].iterations
                    break
                    
            # Start NSEC3 walking
            if self.config.get('nsec3_cracking', {}).get('enabled', True):
                self._crack_nsec3(domain, nsec3_records, wordlist)
                
        except Exception as e:
            self.logger.error(f"Error during NSEC3 walk: {str(e)}")
            
        return nsec3_records

    def _crack_nsec3(self, domain: str, nsec3_records: List[Dict], wordlist: Optional[str] = None) -> None:
        """Attempt to crack NSEC3 hashes using wordlist."""
        max_iterations = self.config.get('nsec3_cracking', {}).get('max_iterations', 1000)
        
        if not wordlist or not os.path.exists(wordlist):
            self.logger.error(f"Wordlist not found: {wordlist}")
            return
            
        try:
            with open(wordlist, 'r') as f:
                words = f.read().splitlines()
                
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.get('threads', 10)) as executor:
                futures = []
                for word in words[:max_iterations]:
                    futures.append(
                        executor.submit(self._test_nsec3_hash, word, domain))
                    
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        nsec3_records.append(result)
                        
        except Exception as e:
            self.logger.error(f"Error during NSEC3 cracking: {str(e)}")

    def _test_nsec3_hash(self, name: str, zone: str) -> Optional[Dict]:
        """Test a single name against NSEC3 hash."""
        try:
            # Create NSEC3 hash
            name = dns.name.from_text(name)
            if not name.is_subdomain(dns.name.from_text(zone)):
                name = name.concatenate(dns.name.from_text(zone))
                
            wire = name.to_wire()
            hash_obj = hashlib.sha1()
            
            # Apply hash iterations
            for _ in range(self.nsec3_iterations + 1):
                hash_obj.update(wire)
                if self.nsec3_salt:
                    hash_obj.update(bytes.fromhex(self.nsec3_salt))
                    
            hash_value = base64.b32encode(hash_obj.digest()).decode('utf-8').lower()
            
            # Query for NSEC3 record
            query = dns.message.make_query(
                f"{hash_value}.{zone}", dns.rdatatype.NSEC3,
                want_dnssec=True)
            response = dns.query.udp(query, self.resolver.nameservers[0])
            
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.NSEC3:
                    return {
                        'name': str(name),
                        'hash': hash_value,
                        'salt': self.nsec3_salt,
                        'iterations': self.nsec3_iterations,
                        'types': [dns.rdatatype.to_text(rtype) 
                                for rtype in rrset[0].windows]
                    }
                    
        except Exception as e:
            pass
            
        return None

    def _verify_chain(self, results: Dict) -> None:
        """Verify the NSEC/NSEC3 chain for completeness."""
        if results.get('nsec_records'):
            self._verify_nsec_chain(results['nsec_records'])
        if results.get('nsec3_records'):
            self._verify_nsec3_chain(results['nsec3_records'])

    def _verify_nsec_chain(self, nsec_records: List[Dict]) -> None:
        """Verify NSEC record chain for gaps."""
        try:
            for i in range(len(nsec_records)):
                current = nsec_records[i]
                next_record = nsec_records[(i + 1) % len(nsec_records)]
                
                if current['next'] != next_record['owner']:
                    self.logger.warning(
                        f"Gap in NSEC chain between {current['owner']} "
                        f"and {next_record['owner']}")
                    
        except Exception as e:
            self.logger.error(f"Error verifying NSEC chain: {str(e)}")

    def _verify_nsec3_chain(self, nsec3_records: List[Dict]) -> None:
        """Verify NSEC3 record chain for gaps."""
        try:
            # Sort records by hash
            sorted_records = sorted(nsec3_records, key=lambda x: x['hash'])
            
            for i in range(len(sorted_records)):
                current = sorted_records[i]
                next_record = sorted_records[(i + 1) % len(sorted_records)]
                
                if current['hash'] >= next_record['hash']:
                    self.logger.warning(
                        f"Potential gap in NSEC3 chain at {current['hash']}")
                    
        except Exception as e:
            self.logger.error(f"Error verifying NSEC3 chain: {str(e)}")

if __name__ == '__main__':
    tool = DNSZoneWalker()
    tool.main() 