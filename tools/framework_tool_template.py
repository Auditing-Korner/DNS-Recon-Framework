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
from typing import Dict, List, Optional, Any

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

class FrameworkTool(BaseTool):
    """Template class for framework-integrated tools"""
    
    def __init__(self, name: str, description: str):
        super().__init__(name=name, description=description)
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing with framework integration support"""
        # Call parent's setup to get standard arguments (--json, --quiet, --debug)
        super().setup_argparse(parser)
        
        # Add framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')
        
        # Add tool-specific arguments here
        self.setup_tool_arguments(parser)
    
    def setup_tool_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Set up tool-specific arguments
        This method should be overridden by subclasses to add their own arguments
        """
        pass
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with framework integration"""
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
            # Run tool-specific logic
            self.execute_tool(args, result)
            
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
    
    def validate_framework_args(self, args: argparse.Namespace) -> bool:
        """
        Validate framework-specific arguments
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            bool: True if validation passes, False otherwise
        """
        if hasattr(args, 'output'):
            try:
                output_dir = os.path.dirname(args.output)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                return True
            except Exception:
                return False
        return True

# Example implementation:
class ExampleTool(FrameworkTool):
    def __init__(self):
        super().__init__(
            name="example-tool",
            description="Example tool implementation"
        )
    
    def setup_tool_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('target', help='Target to analyze')
        parser.add_argument('--option1', help='Example option 1')
        parser.add_argument('--option2', type=int, default=42,
                          help='Example option 2 (default: 42)')
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        # Add target to metadata
        result.metadata['target'] = args.target
        
        # Example finding
        result.add_finding(
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