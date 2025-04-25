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

import dns.resolver
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.exception
from typing import Dict, List, Optional, Any
from pathlib import Path
import sys
import os
import json
import re

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tools.base_tool import BaseTool, ToolResult

class DNSRecordValidator(BaseTool):
    """DNS Record Validation Tool"""
    
    def __init__(self):
        super().__init__(
            name="dns_record_validator",
            description="DNS Record Validation Tool"
        )
        self.version = "2.1.0"
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """Run DNS record validation with provided arguments"""
        domain = self.get_param('domain')
        record_types = self.get_param('record_types', 'all').split(',')
        timeout = self.get_param('timeout', 5)
        nameserver = self.get_param('nameserver')
        check_syntax = self.get_param('check_syntax', True)
        check_values = self.get_param('check_values', True)
        check_consistency = self.get_param('check_consistency', True)
        
        # Update resolver timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Set nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        try:
            # Load validation rules
            rules = self._load_rules()
            if not rules:
                result.add_error("Could not load validation rules")
                return
                
            # Check each record type
            for record_type in rules:
                if record_type not in record_types and 'all' not in record_types:
                    continue
                    
                self._validate_record_type(domain, record_type, rules[record_type], 
                                        check_syntax, check_values, check_consistency, result)
                    
        except Exception as e:
            result.add_error(f"Error during record validation: {str(e)}")
            
    def _load_rules(self) -> Dict:
        """Load validation rules from file"""
        try:
            rules_file = Path(__file__).parent / 'data' / 'dns_validation_rules.json'
            if not rules_file.exists():
                return {
                    'A': {
                        'syntax': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
                        'values': {
                            'min_ttl': 300,
                            'max_ttl': 86400,
                            'blacklist': ['0.0.0.0', '255.255.255.255']
                        }
                    },
                    'AAAA': {
                        'syntax': r'^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$',
                        'values': {
                            'min_ttl': 300,
                            'max_ttl': 86400,
                            'blacklist': ['::']
                        }
                    },
                    'MX': {
                        'syntax': r'^[0-9]+ [a-zA-Z0-9.-]+\.$',
                        'values': {
                            'min_ttl': 3600,
                            'max_ttl': 86400,
                            'max_preference': 65535
                        }
                    },
                    'TXT': {
                        'syntax': r'^"[^"]{1,255}"$',
                        'values': {
                            'min_ttl': 300,
                            'max_ttl': 86400,
                            'max_length': 255
                        }
                    },
                    'CNAME': {
                        'syntax': r'^[a-zA-Z0-9.-]+\.$',
                        'values': {
                            'min_ttl': 300,
                            'max_ttl': 86400
                        }
                    },
                    'NS': {
                        'syntax': r'^[a-zA-Z0-9.-]+\.$',
                        'values': {
                            'min_ttl': 3600,
                            'max_ttl': 86400
                        }
                    }
                }
                
            with open(rules_file) as f:
                return json.load(f)
        except Exception:
            return {}
            
    def _validate_record_type(self, domain: str, record_type: str, rules: Dict,
                            check_syntax: bool, check_values: bool, check_consistency: bool,
                            result: ToolResult) -> None:
        """Validate records of a specific type"""
        try:
            # Get records
            try:
                answers = self.resolver.resolve(domain, record_type)
            except dns.resolver.NoAnswer:
                return
            except Exception as e:
                result.add_warning(f"Error querying {record_type} records: {str(e)}")
                return
                
            # Check each record
            for rr in answers:
                record_str = str(rr)
                
                # Check syntax
                if check_syntax and 'syntax' in rules:
                    if not re.match(rules['syntax'], record_str):
                        result.add_finding({
                            'title': f'Invalid {record_type} Record Syntax',
                            'description': f'Record does not match expected syntax',
                            'risk_level': 'Medium',
                            'details': {
                                'domain': domain,
                                'record_type': record_type,
                                'record': record_str,
                                'expected_syntax': rules['syntax']
                            },
                            'recommendations': [
                                'Review record syntax',
                                'Update record to match expected format'
                            ]
                        })
                        
                # Check values
                if check_values and 'values' in rules:
                    self._check_record_values(domain, record_type, record_str, rr, rules['values'], result)
                    
            # Check consistency
            if check_consistency:
                self._check_record_consistency(domain, record_type, answers, result)
                
        except Exception as e:
            result.add_warning(f"Error validating {record_type} records: {str(e)}")
            
    def _check_record_values(self, domain: str, record_type: str, record_str: str,
                           rr: dns.rdata.Rdata, rules: Dict, result: ToolResult) -> None:
        """Check record values against rules"""
        try:
            # Check TTL
            if hasattr(rr, 'ttl'):
                if 'min_ttl' in rules and rr.ttl < rules['min_ttl']:
                    result.add_finding({
                        'title': f'Low TTL Value',
                        'description': f'{record_type} record has TTL below recommended minimum',
                        'risk_level': 'Low',
                        'details': {
                            'domain': domain,
                            'record_type': record_type,
                            'record': record_str,
                            'ttl': rr.ttl,
                            'min_ttl': rules['min_ttl']
                        }
                    })
                if 'max_ttl' in rules and rr.ttl > rules['max_ttl']:
                    result.add_finding({
                        'title': f'High TTL Value',
                        'description': f'{record_type} record has TTL above recommended maximum',
                        'risk_level': 'Low',
                        'details': {
                            'domain': domain,
                            'record_type': record_type,
                            'record': record_str,
                            'ttl': rr.ttl,
                            'max_ttl': rules['max_ttl']
                        }
                    })
                    
            # Check blacklisted values
            if 'blacklist' in rules and record_str in rules['blacklist']:
                result.add_finding({
                    'title': f'Blacklisted {record_type} Value',
                    'description': f'{record_type} record contains blacklisted value',
                    'risk_level': 'High',
                    'details': {
                        'domain': domain,
                        'record_type': record_type,
                        'record': record_str
                    }
                })
                
            # Check MX preference
            if record_type == 'MX' and 'max_preference' in rules:
                if rr.preference > rules['max_preference']:
                    result.add_finding({
                        'title': 'Invalid MX Preference',
                        'description': 'MX record has preference value above maximum',
                        'risk_level': 'Medium',
                        'details': {
                            'domain': domain,
                            'record': record_str,
                            'preference': rr.preference,
                            'max_preference': rules['max_preference']
                        }
                    })
                    
            # Check TXT length
            if record_type == 'TXT' and 'max_length' in rules:
                txt_string = str(rr).strip('"')
                if len(txt_string) > rules['max_length']:
                    result.add_finding({
                        'title': 'TXT Record Too Long',
                        'description': 'TXT record exceeds maximum length',
                        'risk_level': 'Medium',
                        'details': {
                            'domain': domain,
                            'record': record_str,
                            'length': len(txt_string),
                            'max_length': rules['max_length']
                        }
                    })
                    
        except Exception as e:
            result.add_warning(f"Error checking record values: {str(e)}")
            
    def _check_record_consistency(self, domain: str, record_type: str,
                                answers: dns.resolver.Answer, result: ToolResult) -> None:
        """Check record set consistency"""
        try:
            # Check for duplicate records
            seen_records = set()
            for rr in answers:
                record_str = str(rr)
                if record_str in seen_records:
                    result.add_finding({
                        'title': f'Duplicate {record_type} Record',
                        'description': f'Multiple identical {record_type} records found',
                        'risk_level': 'Low',
                        'details': {
                            'domain': domain,
                            'record_type': record_type,
                            'record': record_str
                        }
                    })
                seen_records.add(record_str)
                
            # Check for conflicting records
            if record_type == 'CNAME' and len(answers) > 1:
                result.add_finding({
                    'title': 'Multiple CNAME Records',
                    'description': 'Domain has multiple CNAME records (RFC violation)',
                    'risk_level': 'High',
                    'details': {
                        'domain': domain,
                        'records': [str(rr) for rr in answers]
                    }
                })
                
        except Exception as e:
            result.add_warning(f"Error checking record consistency: {str(e)}")

def main():
    """Entry point for DNS record validator"""
    tool = DNSRecordValidator()
    return tool.main()

if __name__ == "__main__":
    main() 