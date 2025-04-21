#!/usr/bin/env python3
"""
Base Tool Class

Provides common functionality for all DNS tools:
- Argument parsing
- Result handling
- Error management
- Logging
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional
from datetime import datetime

class ToolResult:
    """Class to handle tool execution results"""
    
    def __init__(self, success: bool, tool_name: str, findings: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None):
        self.success = success
        self.tool_name = tool_name
        self.findings = findings
        self.metadata = metadata or {}
        self.errors = []
        self.start_time = datetime.now()
        
    def add_finding(self, title: str, description: str, risk_level: str, evidence: Optional[str] = None) -> None:
        """Add a finding to the results"""
        finding = {
            'title': title,
            'description': description,
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat()
        }
        if evidence:
            finding['evidence'] = evidence
        self.findings.append(finding)
    
    def add_error(self, message: str) -> None:
        """Add an error message to the results"""
        self.errors.append({
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        self.success = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary"""
        return {
            'status': 'success' if self.success else 'error',
            'tool_name': self.tool_name,
            'findings': self.findings,
            'errors': self.errors,
            'metadata': self.metadata,
            'execution_time': str(datetime.now() - self.start_time)
        }
    
    def __str__(self) -> str:
        """String representation of the result"""
        return json.dumps(self.to_dict(), indent=2)

class BaseTool:
    """Base class for all DNS tools"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing - to be overridden by subclasses"""
        parser.add_argument('--json', action='store_true',
                          help='Output results in JSON format')
        parser.add_argument('--quiet', action='store_true',
                          help='Suppress all output except errors')
        parser.add_argument('--debug', action='store_true',
                          help='Enable debug output')
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool - must be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement run()")
    
    def main(self) -> Dict[str, Any]:
        """Main entry point for the tool"""
        parser = argparse.ArgumentParser(description=self.description)
        self.setup_argparse(parser)
        
        try:
            args = parser.parse_args()
            result = self.run(args)
            
            if not args.quiet:
                if args.json:
                    print(json.dumps(result.to_dict(), indent=2))
                else:
                    self._print_results(result)
            
            return result.to_dict()
            
        except Exception as e:
            if not args.quiet:
                print(f"Error: {str(e)}", file=sys.stderr)
            return {
                'status': 'error',
                'tool_name': self.name,
                'error': str(e)
            }
    
    def _print_results(self, result: ToolResult) -> None:
        """Print results in a human-readable format"""
        print(f"\n=== {self.name.upper()} Results ===\n")
        
        if result.metadata:
            print("Metadata:")
            for key, value in result.metadata.items():
                print(f"  {key}: {value}")
            print()
        
        if result.findings:
            print("Findings:")
            for finding in result.findings:
                print(f"\n[{finding['risk_level']}] {finding['title']}")
                print(f"Description: {finding['description']}")
                if 'evidence' in finding:
                    print(f"Evidence: {finding['evidence']}")
        
        if result.errors:
            print("\nErrors:")
            for error in result.errors:
                print(f"  - {error['message']}")
        
        print(f"\nExecution time: {datetime.now() - result.start_time}")
        print(f"Status: {'Success' if result.success else 'Failed'}\n") 