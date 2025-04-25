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
import os
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from rich.console import Console

class ToolResult:
    """Class to store and manage tool execution results"""
    
    def __init__(self, success: bool = True, tool_name: str = "", findings: List[Dict] = None):
        self.success = success
        self.tool_name = tool_name
        self.findings = findings or []
        self.messages = []
        self.warnings = []
        self.errors = []
        self.metadata = {
            "timestamp": datetime.now().isoformat(),
            "tool_name": tool_name
        }
        
    def add_finding(self, finding: Dict) -> None:
        """Add a finding to the results"""
        self.findings.append(finding)
        
    def add_message(self, message: str) -> None:
        """Add an informational message"""
        self.messages.append(message)
        
    def add_warning(self, warning: str) -> None:
        """Add a warning message"""
        self.warnings.append(warning)
        
    def add_error(self, error: str) -> None:
        """Add an error message"""
        self.errors.append(error)
        
    def add_info(self, info: str) -> None:
        """Add an informational message (alias for add_message)"""
        self.add_message(info)
        
    def to_dict(self) -> Dict:
        """Convert results to dictionary format"""
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "findings": self.findings,
            "messages": self.messages,
            "warnings": self.warnings,
            "errors": self.errors,
            "metadata": self.metadata
        }

class BaseTool:
    """Base class for all framework tools"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.version = "1.0.0"
        self._params = {}
        self._result = None
        self.console = Console()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.framework_mode = False
        
    def get_param(self, name: str, default: Any = None) -> Any:
        """Get a parameter value by name"""
        return self._params.get(name, default)
        
    def get_params(self) -> Dict[str, Any]:
        """Get all parameters"""
        return self._params
        
    def set_param(self, name: str, value: Any) -> None:
        """Set a parameter value"""
        self._params[name] = value
        
    def set_params(self, params: Dict[str, Any]) -> None:
        """Set multiple parameters"""
        self._params.update(params)
        
    def get_result(self) -> ToolResult:
        """Get the tool result object"""
        if self._result is None:
            self._result = ToolResult(tool_name=self.name)
        return self._result
        
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """
        Run the tool implementation. Must be overridden by subclasses.
        
        Args:
            args: The parsed arguments
            result: ToolResult object to store findings
        """
        raise NotImplementedError("Tool must implement _run_tool method")
        
    def main(self) -> Dict:
        """Main entry point for running the tool"""
        try:
            # Create result object
            result = self.get_result()
            
            # Get args from framework parameters
            args = argparse.Namespace()
            for key, value in self._params.items():
                setattr(args, key, value)
            
            # Run the tool
            self._run_tool(args, result)
            
            return result.to_dict()
            
        except Exception as e:
            result = self.get_result()
            result.success = False
            result.add_error(f"Error running tool '{self.name}': {str(e)}")
            return result.to_dict()
            
    def run(self, params: Dict[str, Any] = None) -> Dict:
        """Run the tool with the given parameters"""
        if params:
            self.set_params(params)
        return self.main()

    def log_message(self, level: str, message: str, context: Optional[Dict] = None):
        """Unified logging that respects framework mode"""
        if self.framework_mode:
            if level == "error":
                self._result.add_error(message)
            elif level == "warning":
                self._result.add_warning(message)
            else:
                self._result.add_message(message)
        else:
            if level == "error":
                self.logger.error(message)
            elif level == "warning":
                self.logger.warning(message)
            else:
                self.logger.info(message)

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
                risk_level = finding.get('risk_level', 'Info')
                print(f"\n[{risk_level}] {finding.get('title', 'Untitled Finding')}")
                if 'description' in finding:
                    print(f"Description: {finding['description']}")
                if 'details' in finding:
                    print("Details:")
                    if isinstance(finding['details'], dict):
                        for key, value in finding['details'].items():
                            print(f"  {key}: {value}")
                    else:
                        print(f"  {finding['details']}")
                if 'recommendations' in finding:
                    print("\nRecommendations:")
                    for rec in finding['recommendations']:
                        print(f"  - {rec}")
            print()
        
        if result.errors:
            print("\nErrors:")
            for error in result.errors:
                print(f"  - {error}")
        
        if result.warnings:
            print("\nWarnings:")
            for warning in result.warnings:
                print(f"  - {warning}")
        
        print(f"\nStatus: {result.success}")
        print(f"Execution time: {result.metadata['timestamp']}")

def load_tool(tool_name: str) -> Optional[BaseTool]:
    """Load a tool by name"""
    try:
        # Add the parent directory to sys.path
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent_dir not in sys.path:
            sys.path.append(parent_dir)
            
        # Import the tool module
        module = __import__(f"tools.{tool_name}", fromlist=["main"])
        return module.main()
    except ImportError as e:
        print(f"Error loading {tool_name}: {str(e)}")
        return None 