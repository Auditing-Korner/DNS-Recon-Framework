#!/usr/bin/env python3
"""
DNS Record Validator Tool

Validates DNS records for correctness, consistency, and best practices:
- Record syntax validation
- TTL analysis
- SPF/DMARC/DKIM validation
- Record conflicts detection
- Best practices compliance
- DNS configuration recommendations
"""

import argparse
import concurrent.futures
import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
import re
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class DNSRecordValidator(BaseTool):
    """DNS Record Validation and Best Practices Analysis Tool"""
    
    def __init__(self):
        super().__init__(
            name="dns-record-validator",
            description="DNS Record Validation and Best Practices Analysis"
        )
        self.domain = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
        # Initialize validation rules
        self.validation_rules = {
            'TTL': {
                'min': 300,  # 5 minutes
                'max': 86400,  # 24 hours
                'recommended': 3600  # 1 hour
            },
            'SPF': {
                'max_lookups': 10,
                'max_length': 255,
                'required_tags': ['v=spf1'],
                'recommended_tags': ['~all', '-all']
            },
            'DMARC': {
                'required_tags': ['v=DMARC1', 'p='],
                'recommended_tags': ['rua=', 'ruf=', 'pct=100']
            },
            'MX': {
                'max_records': 10,
                'require_backup': True
            },
            'NS': {
                'min_records': 2,
                'max_records': 13,
                'recommended_records': 4
            }
        }

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        parser.add_argument('domain', help='Target domain to validate')
        parser.add_argument('--check-spf', action='store_true',
                          help='Validate SPF records')
        parser.add_argument('--check-dmarc', action='store_true',
                          help='Validate DMARC records')
        parser.add_argument('--check-dkim', action='store_true',
                          help='Check for DKIM records')
        parser.add_argument('--check-ttl', action='store_true',
                          help='Analyze TTL values')
        parser.add_argument('--check-all', action='store_true',
                          help='Run all validation checks')
        parser.add_argument('--timeout', type=int, default=5,
                          help='Timeout for DNS queries in seconds')
        
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the validation checks"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": args.domain,
                "framework_mode": args.framework_mode if hasattr(args, 'framework_mode') else False,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        try:
            self.domain = args.domain
            self.resolver.timeout = args.timeout
            self.resolver.lifetime = args.timeout
            
            # Determine which checks to run
            run_all = args.check_all
            checks = {
                'spf': run_all or args.check_spf,
                'dmarc': run_all or args.check_dmarc,
                'dkim': run_all or args.check_dkim,
                'ttl': run_all or args.check_ttl
            }
            
            # Run validations
            if checks['spf']:
                self._validate_spf(result)
            if checks['dmarc']:
                self._validate_dmarc(result)
            if checks['dkim']:
                self._check_dkim(result)
            if checks['ttl']:
                self._analyze_ttl(result)
            
            # Always run basic record validations
            self._validate_basic_records(result)
            
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
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during validation: {str(e)}")
            return result

    def _validate_basic_records(self, result: ToolResult) -> None:
        """Validate basic DNS records (A, MX, NS, etc.)"""
        try:
            # Check NS records
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                ns_count = len(ns_records)
                
                if ns_count < self.validation_rules['NS']['min_records']:
                    result.add_finding(
                        title="Insufficient NS Records",
                        description=f"Only {ns_count} NS records found. Minimum recommended is {self.validation_rules['NS']['min_records']}",
                        risk_level="High"
                    )
                elif ns_count > self.validation_rules['NS']['max_records']:
                    result.add_finding(
                        title="Excessive NS Records",
                        description=f"Found {ns_count} NS records. Maximum recommended is {self.validation_rules['NS']['max_records']}",
                        risk_level="Medium"
                    )
            except Exception as e:
                result.add_finding(
                    title="NS Record Error",
                    description=f"Error checking NS records: {str(e)}",
                    risk_level="High"
                )
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                mx_count = len(mx_records)
                
                if mx_count == 0:
                    result.add_finding(
                        title="No MX Records",
                        description="No MX records found. This will prevent email delivery.",
                        risk_level="High"
                    )
                elif mx_count == 1 and self.validation_rules['MX']['require_backup']:
                    result.add_finding(
                        title="Single MX Record",
                        description="Only one MX record found. Consider adding a backup mail server.",
                        risk_level="Medium"
                    )
                elif mx_count > self.validation_rules['MX']['max_records']:
                    result.add_finding(
                        title="Excessive MX Records",
                        description=f"Found {mx_count} MX records. This may cause performance issues.",
                        risk_level="Low"
                    )
            except Exception as e:
                result.add_finding(
                    title="MX Record Error",
                    description=f"Error checking MX records: {str(e)}",
                    risk_level="Medium"
                )
            
            # Check A/AAAA records
            try:
                has_a = False
                has_aaaa = False
                
                try:
                    a_records = dns.resolver.resolve(self.domain, 'A')
                    has_a = len(a_records) > 0
                except:
                    pass
                
                try:
                    aaaa_records = dns.resolver.resolve(self.domain, 'AAAA')
                    has_aaaa = len(aaaa_records) > 0
                except:
                    pass
                
                if not has_a and not has_aaaa:
                    result.add_finding(
                        title="No Address Records",
                        description="No A or AAAA records found for the domain",
                        risk_level="High"
                    )
                elif not has_aaaa:
                    result.add_finding(
                        title="No IPv6 Support",
                        description="No AAAA records found. Consider adding IPv6 support.",
                        risk_level="Low"
                    )
            except Exception as e:
                result.add_finding(
                    title="Address Record Error",
                    description=f"Error checking address records: {str(e)}",
                    risk_level="Medium"
                )
                
        except Exception as e:
            result.add_error(f"Error in basic record validation: {str(e)}")

    def _validate_spf(self, result: ToolResult) -> None:
        """Validate SPF records"""
        try:
            spf_records = []
            try:
                txt_records = dns.resolver.resolve(self.domain, 'TXT')
                for record in txt_records:
                    for string in record.strings:
                        if string.decode().startswith('v=spf1'):
                            spf_records.append(string.decode())
            except dns.resolver.NoAnswer:
                pass
            
            if not spf_records:
                result.add_finding(
                    title="Missing SPF Record",
                    description="No SPF record found. This may allow email spoofing.",
                    risk_level="High"
                )
                return
            
            if len(spf_records) > 1:
                result.add_finding(
                    title="Multiple SPF Records",
                    description="Multiple SPF records found. This is invalid and may cause issues.",
                    risk_level="High"
                )
            
            spf = spf_records[0]
            
            # Check length
            if len(spf) > self.validation_rules['SPF']['max_length']:
                result.add_finding(
                    title="SPF Record Too Long",
                    description=f"SPF record exceeds {self.validation_rules['SPF']['max_length']} characters",
                    risk_level="Medium"
                )
            
            # Check for recommended tags
            if not any(tag in spf for tag in self.validation_rules['SPF']['recommended_tags']):
                result.add_finding(
                    title="Weak SPF Policy",
                    description="SPF record does not specify a strong policy (~all or -all)",
                    risk_level="Medium"
                )
            
            # Count DNS lookups
            lookup_mechanisms = ['include:', 'a:', 'mx:', 'ptr:', 'exists:']
            lookup_count = sum(spf.count(mech) for mech in lookup_mechanisms)
            
            if lookup_count > self.validation_rules['SPF']['max_lookups']:
                result.add_finding(
                    title="Excessive SPF Lookups",
                    description=f"SPF record requires {lookup_count} DNS lookups (max {self.validation_rules['SPF']['max_lookups']})",
                    risk_level="Medium"
                )
                
        except Exception as e:
            result.add_finding(
                title="SPF Validation Error",
                description=f"Error validating SPF record: {str(e)}",
                risk_level="Medium"
            )

    def _validate_dmarc(self, result: ToolResult) -> None:
        """Validate DMARC records"""
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            try:
                txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                dmarc_records = []
                
                for record in txt_records:
                    for string in record.strings:
                        if string.decode().startswith('v=DMARC1'):
                            dmarc_records.append(string.decode())
                
                if not dmarc_records:
                    result.add_finding(
                        title="Missing DMARC Record",
                        description="No DMARC record found. Email authentication is incomplete.",
                        risk_level="High"
                    )
                    return
                
                if len(dmarc_records) > 1:
                    result.add_finding(
                        title="Multiple DMARC Records",
                        description="Multiple DMARC records found. This is invalid.",
                        risk_level="High"
                    )
                
                dmarc = dmarc_records[0]
                
                # Check required tags
                for tag in self.validation_rules['DMARC']['required_tags']:
                    if tag not in dmarc:
                        result.add_finding(
                            title="Invalid DMARC Record",
                            description=f"Missing required DMARC tag: {tag}",
                            risk_level="High"
                        )
                
                # Check policy strength
                if 'p=none' in dmarc:
                    result.add_finding(
                        title="Weak DMARC Policy",
                        description="DMARC policy is set to 'none'",
                        risk_level="Medium"
                    )
                
                # Check recommended tags
                missing_recommended = [tag for tag in self.validation_rules['DMARC']['recommended_tags']
                                    if tag not in dmarc]
                if missing_recommended:
                    result.add_finding(
                        title="Incomplete DMARC Configuration",
                        description=f"Missing recommended DMARC tags: {', '.join(missing_recommended)}",
                        risk_level="Low"
                    )
                    
            except dns.resolver.NXDOMAIN:
                result.add_finding(
                    title="Missing DMARC Record",
                    description="No DMARC record found. Email authentication is incomplete.",
                    risk_level="High"
                )
            except Exception as e:
                result.add_finding(
                    title="DMARC Resolution Error",
                    description=f"Error resolving DMARC record: {str(e)}",
                    risk_level="Medium"
                )
                
        except Exception as e:
            result.add_finding(
                title="DMARC Validation Error",
                description=f"Error validating DMARC record: {str(e)}",
                risk_level="Medium"
            )

    def _check_dkim(self, result: ToolResult) -> None:
        """Check for DKIM records"""
        try:
            # Common DKIM selectors
            selectors = ['default', 'google', 'selector1', 'selector2', 'dkim']
            
            found_dkim = False
            for selector in selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{self.domain}"
                    dns.resolver.resolve(dkim_domain, 'TXT')
                    found_dkim = True
                    break
                except:
                    continue
            
            if not found_dkim:
                result.add_finding(
                    title="No DKIM Records Found",
                    description="No DKIM records found with common selectors. Email authentication is incomplete.",
                    risk_level="Medium"
                )
                
        except Exception as e:
            result.add_finding(
                title="DKIM Check Error",
                description=f"Error checking DKIM records: {str(e)}",
                risk_level="Low"
            )

    def _analyze_ttl(self, result: ToolResult) -> None:
        """Analyze TTL values for various records"""
        try:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, rtype)
                    for answer in answers:
                        ttl = answer.ttl
                        
                        if ttl < self.validation_rules['TTL']['min']:
                            result.add_finding(
                                title=f"Low TTL Value ({rtype})",
                                description=f"TTL for {rtype} record is {ttl}s (min recommended: {self.validation_rules['TTL']['min']}s)",
                                risk_level="Low"
                            )
                        elif ttl > self.validation_rules['TTL']['max']:
                            result.add_finding(
                                title=f"High TTL Value ({rtype})",
                                description=f"TTL for {rtype} record is {ttl}s (max recommended: {self.validation_rules['TTL']['max']}s)",
                                risk_level="Low"
                            )
                except:
                    continue
                    
        except Exception as e:
            result.add_finding(
                title="TTL Analysis Error",
                description=f"Error analyzing TTL values: {str(e)}",
                risk_level="Low"
            )

def main():
    """Main function for standalone usage"""
    tool = DNSRecordValidator()
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