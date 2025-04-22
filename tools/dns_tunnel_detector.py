#!/usr/bin/env python3

import dns.message
import dns.resolver
import dns.rdatatype
import dns.name
import logging
import yaml
import math
import re
import time
import sys
import os
import json
import argparse
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

# Handle imports for framework integration
try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class DNSTunnelDetector(BaseTool):
    """DNS Tunneling Detection tool using multiple detection methods."""
    
    def __init__(self):
        """Initialize the DNS Tunnel Detector."""
        super().__init__(
            name="tunnel-detector",
            description="Detect DNS Tunneling and Data Exfiltration"
        )
        self.query_history = deque(maxlen=10000)  # Will be updated from config
        self.known_tunnels: Set[str] = set()
        self.signatures = []
        
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool."""
        parser.add_argument('--pcap',
                          help='PCAP file to analyze')
        parser.add_argument('--query',
                          help='Single query to analyze')
        parser.add_argument('--qtype', default='A',
                          help='Query type for single query analysis')
        parser.add_argument('--no-statistical', action='store_true',
                          help='Disable statistical analysis')
        parser.add_argument('--no-entropy', action='store_true',
                          help='Disable entropy analysis')
        parser.add_argument('--no-pattern', action='store_true',
                          help='Disable pattern matching')
        parser.add_argument('--no-signature', action='store_true',
                          help='Disable signature-based detection')
        
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')
        
    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if required dependencies are available."""
        missing = []
        
        try:
            import dns.resolver
        except ImportError:
            missing.append("dnspython")
            
        try:
            import numpy
        except ImportError:
            missing.append("numpy")
            
        if missing:
            return False, f"Missing required packages: {', '.join(missing)}"
            
        return True, None

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tunnel detection analysis."""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "timestamp": datetime.now().isoformat(),
                "framework_mode": args.framework_mode if hasattr(args, 'framework_mode') else False,
                "detection_methods": {
                    "statistical": not args.no_statistical,
                    "entropy": not args.no_entropy,
                    "pattern_matching": not args.no_pattern,
                    "signature_based": not args.no_signature
                }
            }
        )

        try:
            # Check dependencies
            deps_ok, error_msg = self.check_dependencies()
            if not deps_ok:
                result.add_error(error_msg)
                return result
            
            # Load configuration and signatures
            self._load_config()
            
            if args.pcap:
                # Analyze PCAP file
                results = self.analyze_pcap(args.pcap)
                
                if results.get('error'):
                    result.add_error(results['error'])
                else:
                    result.metadata.update({
                        'analyzed_queries': results['analyzed_queries'],
                        'tunnel_detected': results['tunnel_detected']
                    })
                    
                    if results['detections']:
                        for detection in results['detections']:
                            confidence = detection['confidence']
                            risk_level = self._get_severity_from_confidence(confidence)
                            
                            result.add_finding(
                                title="DNS Tunnel Detected",
                                description=f"Detected potential DNS tunneling (confidence: {confidence:.2f})",
                                risk_level=risk_level.capitalize(),
                                evidence=json.dumps({
                                    'query': detection['query'],
                                    'qtype': detection['qtype'],
                                    'indicators': {
                                        'statistical': detection['statistical_indicators'],
                                        'entropy': detection['entropy_score'],
                                        'patterns': detection['pattern_matches'],
                                        'signatures': detection['signature_matches']
                                    }
                                }, indent=2)
                            )
                    
                    # Add summary to metadata
                    result.metadata['summary'] = results['summary']
                    
            elif args.query:
                # Analyze single query
                results = self.analyze_query(args.query, args.qtype, time.time())
                
                if results['is_tunnel']:
                    confidence = results['confidence']
                    risk_level = self._get_severity_from_confidence(confidence)
                    
                    result.add_finding(
                        title="DNS Tunnel Detected",
                        description=f"Query matches tunnel characteristics (confidence: {confidence:.2f})",
                        risk_level=risk_level.capitalize(),
                        evidence=json.dumps({
                            'query': results['query'],
                            'qtype': results['qtype'],
                            'indicators': {
                                'statistical': results['statistical_indicators'],
                                'entropy': results['entropy_score'],
                                'patterns': results['pattern_matches'],
                                'signatures': results['signature_matches']
                            }
                        }, indent=2)
                    )
            else:
                result.add_error("No input specified. Use --pcap or --query")
            
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
            result.add_error(f"Error during tunnel detection: {str(e)}")
            return result

    def _load_config(self) -> None:
        """Load configuration from framework config."""
        try:
            with open("config.yaml", 'r') as f:
                config = yaml.safe_load(f)
            self.config = config.get('tools', {}).get('tunnel_detector', {})
            
            # Update query history size from config
            max_history = self.config.get('analysis', {}).get('max_history', 10000)
            self.query_history = deque(maxlen=max_history)
            
            # Load signatures
            self._load_signatures()
            
        except Exception as e:
            self.logger.warning(f"Error loading config: {e}")
            self.config = {}

    def _get_severity_from_confidence(self, confidence: float) -> str:
        """Convert confidence score to severity level."""
        if confidence >= 0.9:
            return "Critical"
        elif confidence >= 0.7:
            return "High"
        elif confidence >= 0.5:
            return "Medium"
        else:
            return "Low"

    def _load_signatures(self) -> List[Dict]:
        """Load tunnel signatures from configuration."""
        signatures = []
        sig_config = self.config.get('detection_methods', {}).get('signature_based', {})
        
        if sig_config.get('enabled', True):
            signatures = sig_config.get('signatures', [])
            self.logger.info(f"Loaded {len(signatures)} tunnel signatures")
            
        return signatures

    def analyze_query(self, query: str, qtype: str, timestamp: float) -> Dict:
        """Analyze a single DNS query for tunneling indicators."""
        results = {
            'query': query,
            'qtype': qtype,
            'timestamp': timestamp,
            'statistical_indicators': {},
            'entropy_score': 0.0,
            'pattern_matches': [],
            'signature_matches': [],
            'is_tunnel': False,
            'confidence': 0.0
        }
        
        # Add query to history
        self.query_history.append((query, qtype, timestamp))
        
        # Run enabled detection methods
        detection_methods = self.config.get('detection_methods', {})
        
        if detection_methods.get('statistical', {}).get('enabled', True):
            results['statistical_indicators'] = self._statistical_analysis(query)
            
        if detection_methods.get('entropy', {}).get('enabled', True):
            results['entropy_score'] = self._entropy_analysis(query)
            
        if detection_methods.get('pattern_matching', {}).get('enabled', True):
            results['pattern_matches'] = self._pattern_analysis(query)
            
        if detection_methods.get('signature_based', {}).get('enabled', True):
            results['signature_matches'] = self._signature_analysis(query, qtype)
            
        # Determine if query is likely tunneling
        results['is_tunnel'], results['confidence'] = self._evaluate_results(results)
        
        # Log if tunnel detected
        if results['is_tunnel']:
            self._log_tunnel_detection(results)
            
        return results

    def _statistical_analysis(self, query: str) -> Dict:
        """Perform statistical analysis on query."""
        stats = {
            'length': len(query),
            'subdomain_count': len(query.split('.')) - 1,
            'unique_chars': len(set(query)),
            'digit_ratio': sum(c.isdigit() for c in query) / len(query) if query else 0,
            'consonant_ratio': len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', query.lower())) / len(query) if query else 0
        }
        
        # Add time-based statistics
        if len(self.query_history) >= 2:
            recent_queries = [q for q, _, t in self.query_history 
                            if t >= time.time() - self.config.get('analysis', {}).get('time_window', 300)]
            stats['query_frequency'] = len(recent_queries) / self.config.get('analysis', {}).get('time_window', 300)
            
            if recent_queries:
                stats['avg_query_length'] = sum(len(q) for q in recent_queries) / len(recent_queries)
                stats['unique_subdomains'] = len(set('.'.join(q.split('.')[:-1]) for q in recent_queries))
        
        return stats

    def _entropy_analysis(self, query: str) -> float:
        """Calculate Shannon entropy of query string."""
        if not query:
            return 0.0
            
        # Calculate character frequencies
        freq = defaultdict(int)
        for char in query:
            freq[char] += 1
            
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            probability = count / len(query)
            entropy -= probability * math.log2(probability)
            
        return entropy

    def _pattern_analysis(self, query: str) -> List[str]:
        """Check for suspicious patterns in query."""
        patterns = []
        pattern_config = self.config.get('detection_methods', {}).get('pattern_matching', {})
        
        # Check for base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', query):
            patterns.append('base64_encoded')
            
        # Check for hex encoding
        if re.search(r'[0-9a-fA-F]{20,}', query):
            patterns.append('hex_encoded')
            
        # Check for long numeric sequences
        if re.search(r'\d{10,}', query):
            patterns.append('long_numeric')
            
        # Check for repeated patterns
        subdomains = query.split('.')
        for subdomain in subdomains:
            if len(subdomain) >= 20 and self._has_repeating_pattern(subdomain):
                patterns.append('repeating_pattern')
                break
                
        return patterns

    def _signature_analysis(self, query: str, qtype: str) -> List[str]:
        """Match query against known tunnel signatures."""
        matches = []
        
        for signature in self.signatures:
            if 'pattern' in signature:
                if re.search(signature['pattern'], query, re.IGNORECASE):
                    matches.append(signature['name'])
                    
            if 'qtype' in signature and signature['qtype'] == qtype:
                if 'subdomain_length' in signature:
                    subdomains = query.split('.')
                    if any(len(sub) >= signature['subdomain_length'] for sub in subdomains):
                        matches.append(signature['name'])
                        
        return matches

    def _evaluate_results(self, results: Dict) -> Tuple[bool, float]:
        """Evaluate all detection results to determine if query is tunneling."""
        confidence_scores = []
        
        # Statistical indicators
        stats = results['statistical_indicators']
        if stats:
            # Length-based confidence
            if stats['length'] > 50:
                confidence_scores.append(0.3)
            if stats['length'] > 100:
                confidence_scores.append(0.5)
                
            # Subdomain-based confidence
            if stats['subdomain_count'] > 3:
                confidence_scores.append(0.2)
            if stats['subdomain_count'] > 5:
                confidence_scores.append(0.4)
                
            # Character diversity confidence
            char_ratio = stats['unique_chars'] / stats['length']
            if char_ratio > 0.7:
                confidence_scores.append(0.4)
                
        # Entropy-based confidence
        entropy_threshold = self.config.get('detection_methods', {}).get('entropy', {}).get('threshold', 0.7)
        if results['entropy_score'] > entropy_threshold:
            confidence_scores.append(0.6)
            
        # Pattern-based confidence
        if results['pattern_matches']:
            confidence_scores.append(0.7)
            
        # Signature-based confidence
        if results['signature_matches']:
            confidence_scores.append(0.9)
            
        # Calculate final confidence
        if confidence_scores:
            confidence = max(confidence_scores)
            threshold = self.config.get('analysis', {}).get('confidence_threshold', 0.6)
            return confidence >= threshold, confidence
            
        return False, 0.0

    def _has_repeating_pattern(self, text: str, min_pattern_length: int = 3) -> bool:
        """Check if string contains repeating patterns."""
        for i in range(min_pattern_length, len(text) // 2 + 1):
            pattern = text[:i]
            if pattern * (len(text) // len(pattern)) in text:
                return True
        return False

    def _log_tunnel_detection(self, results: Dict) -> None:
        """Log tunnel detection with details."""
        if self.config.get('logging', {}).get('enabled', True):
            log_msg = [
                f"DNS Tunnel Detected:",
                f"Query: {results['query']}",
                f"Type: {results['qtype']}",
                f"Confidence: {results['confidence']:.2f}",
                "Indicators:"
            ]
            
            if results['statistical_indicators']:
                log_msg.append("  Statistical:")
                for k, v in results['statistical_indicators'].items():
                    log_msg.append(f"    {k}: {v}")
                    
            if results['entropy_score']:
                log_msg.append(f"  Entropy Score: {results['entropy_score']:.2f}")
                
            if results['pattern_matches']:
                log_msg.append("  Pattern Matches:")
                for pattern in results['pattern_matches']:
                    log_msg.append(f"    - {pattern}")
                    
            if results['signature_matches']:
                log_msg.append("  Signature Matches:")
                for sig in results['signature_matches']:
                    log_msg.append(f"    - {sig}")
                    
            self.logger.warning('\n'.join(log_msg))

    def analyze_pcap(self, pcap_file: str) -> Dict:
        """Analyze DNS queries from a PCAP file."""
        try:
            import scapy.all as scapy
        except ImportError:
            self.logger.error("Scapy is required for PCAP analysis. Please install it with: pip install scapy")
            return {'error': 'Scapy not installed'}
            
        results = {
            'analyzed_queries': 0,
            'tunnel_detected': False,
            'detections': [],
            'summary': {}
        }
        
        try:
            # Read PCAP file
            packets = scapy.rdpcap(pcap_file)
            
            # Process DNS queries
            for packet in packets:
                if packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0:
                    dns = packet.getlayer(scapy.DNS)
                    for i in range(dns.qdcount):
                        query = dns.qd[i].qname.decode('utf-8').rstrip('.')
                        qtype = dns.qd[i].qtype
                        timestamp = float(packet.time)
                        
                        # Analyze query
                        analysis = self.analyze_query(query, qtype, timestamp)
                        results['analyzed_queries'] += 1
                        
                        if analysis['is_tunnel']:
                            results['tunnel_detected'] = True
                            results['detections'].append(analysis)
                            
            # Generate summary
            results['summary'] = self._generate_summary(results['detections'])
            
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP file: {str(e)}")
            results['error'] = str(e)
            
        return results

    def _generate_summary(self, detections: List[Dict]) -> Dict:
        """Generate summary of tunnel detections."""
        summary = {
            'total_detections': len(detections),
            'unique_patterns': set(),
            'unique_signatures': set(),
            'confidence_stats': {
                'min': 1.0,
                'max': 0.0,
                'avg': 0.0
            }
        }
        
        if not detections:
            return summary
            
        # Collect unique patterns and signatures
        confidences = []
        for detection in detections:
            summary['unique_patterns'].update(detection['pattern_matches'])
            summary['unique_signatures'].update(detection['signature_matches'])
            confidences.append(detection['confidence'])
            
        # Calculate confidence statistics
        summary['confidence_stats'] = {
            'min': min(confidences),
            'max': max(confidences),
            'avg': sum(confidences) / len(confidences)
        }
        
        # Convert sets to lists for JSON serialization
        summary['unique_patterns'] = list(summary['unique_patterns'])
        summary['unique_signatures'] = list(summary['unique_signatures'])
        
        return summary

def main():
    """Main function for standalone usage"""
    tool = DNSTunnelDetector()
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