#!/usr/bin/env python3
"""
Framework Tool Template

Base template for implementing tools with proper framework integration:
- Standard argument parsing
- Output file handling
- Framework mode support
- Result formatting
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any, Union

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class FrameworkTool(BaseTool):
    """Template class for framework-integrated tools"""
    
    def __init__(self, name: str, description: str):
        super().__init__(name=name, description=description)
        self._framework_mode = False
        self._output_file = None
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing with framework integration support"""
        # Create argument groups for better organization
        framework_group = parser.add_argument_group('framework options')
        tool_group = parser.add_argument_group('tool options')
        
        # Add framework integration arguments
        framework_group.add_argument('--output', help='Output file path for results')
        framework_group.add_argument('--framework-mode', action='store_true',
                                   help='Run in framework integration mode')
        
        # Add common arguments
        tool_group.add_argument('--json', action='store_true',
                              help='Output results in JSON format')
        tool_group.add_argument('--quiet', action='store_true',
                              help='Suppress non-essential output')
        tool_group.add_argument('--debug', action='store_true',
                              help='Enable debug logging')
        
        # Add tool-specific arguments
        self.setup_tool_arguments(tool_group)
    
    def setup_tool_arguments(self, parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup]) -> None:
        """
        Set up tool-specific arguments
        This method should be overridden by subclasses to add their own arguments
        
        Args:
            parser: ArgumentParser or argument group for adding tool-specific arguments
        """
        pass
    
    def run(self, args: Optional[argparse.Namespace] = None) -> ToolResult:
        """Run the tool with framework integration"""
        # Handle case where args is None (direct run() call)
        if args is None:
            parser = argparse.ArgumentParser(description=self.description)
            self.setup_argparse(parser)
            args = parser.parse_args()
        
        # Initialize result
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "framework_mode": args.framework_mode if hasattr(args, 'framework_mode') else False,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        try:
            # Store framework mode state
            self._framework_mode = getattr(args, 'framework_mode', False)
            self._output_file = getattr(args, 'output', None)
            
            # Run tool-specific logic
            self.execute_tool(args, result)
            
            # Handle output file if specified
            if self._output_file:
                try:
                    output_dir = os.path.dirname(self._output_file)
                    if output_dir and not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    
                    with open(self._output_file, 'w') as f:
                        json.dump(result.to_dict(), f, indent=2)
                except Exception as e:
                    result.add_error(f"Error writing output file: {str(e)}")
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during execution: {str(e)}")
            return result
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        """
        Execute tool-specific logic
        This method must be implemented by subclasses
        
        Args:
            args: Parsed command line arguments
            result: ToolResult object to store findings and errors
        """
        raise NotImplementedError("Subclasses must implement execute_tool()")
    
    def is_framework_mode(self) -> bool:
        """Check if tool is running in framework mode"""
        return self._framework_mode
    
    def get_output_file(self) -> Optional[str]:
        """Get configured output file path"""
        return self._output_file
    
    @staticmethod
    def add_common_finding(result: ToolResult, title: str, description: str,
                          risk_level: str = "Info", evidence: Optional[str] = None) -> None:
        """Helper method to add a finding with consistent formatting"""
        result.add_finding(
            title=title,
            description=description,
            risk_level=risk_level,
            evidence=evidence if evidence else "No specific evidence provided"
        )

# Example implementation:
class ExampleTool(FrameworkTool):
    def __init__(self):
        super().__init__(
            name="example-tool",
            description="Example tool implementation"
        )
    
    def setup_tool_arguments(self, parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup]) -> None:
        parser.add_argument('target', help='Target to analyze')
        parser.add_argument('--option1', help='Example option 1')
        parser.add_argument('--option2', type=int, default=42,
                          help='Example option 2 (default: 42)')
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        # Add target to metadata
        result.metadata['target'] = args.target
        
        # Example finding using helper method
        self.add_common_finding(
            result,
            title="Example Finding",
            description="This is an example finding",
            risk_level="Info",
            evidence=f"Option1: {args.option1}, Option2: {args.option2}"
        )

def main():
    tool = ExampleTool()
    return tool.main()

if __name__ == "__main__":
    sys.exit(0 if main()['status'] == 'success' else 1) 