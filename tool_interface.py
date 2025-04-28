#!/usr/bin/env python3
"""
Tool Interface Module

Defines base classes and interfaces for framework tools:
- BaseTool: Basic tool functionality
- FrameworkTool: Enhanced framework integration
- ToolResult: Standardized result format
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from rich.console import Console
import argparse
from jinja2 import Template

class ToolResult:
    """Class to store and format tool execution results"""
    
    def __init__(self, tool_name: str = "", success: bool = True):
        self.tool_name = tool_name
        self.success = success
        self.findings = []
        self.errors = []
        self.metadata = {}
        self.start_time = datetime.now()
        
    def add_finding(self, title: str, description: str, risk_level: str = "Info", evidence: Any = None) -> None:
        """Add a finding to the results"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk_level,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        })
        
    def add_error(self, message: str) -> None:
        """Add an error message to the results"""
        self.errors.append({
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
    def to_dict(self) -> Dict:
        """Convert results to dictionary format"""
        return {
            'tool_name': self.tool_name,
            'success': self.success,
            'findings': self.findings,
            'errors': self.errors,
            'metadata': self.metadata,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat()
        }

class BaseTool(ABC):
    """Base class for all framework tools"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.version = "1.0.0"
        self._params = {}
        self._result = None
        self.logger = logging.getLogger(self.name)
        self.framework_mode = False
        self.console = Console()
        
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')
        
    def run(self, args: Any) -> Dict:
        """Run the tool with the given arguments"""
        # Initialize result
        result = ToolResult(tool_name=self.name)
        
        try:
            # Store parameters
            if isinstance(args, dict):
                self._params = args
            else:
                self._params = vars(args)
            
            # Set framework mode
            self.framework_mode = self._params.get('framework_mode', False)
            
            # Run the tool implementation
            self._run_tool(args, result)
            
            # Handle output file if specified
            output_file = self._params.get('output')
            if output_file:
                self._save_results(result, output_file)
            
            return result.to_dict()
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error running tool: {str(e)}")
            return result.to_dict()
    
    def _run_tool(self, args: Any, result: ToolResult) -> None:
        """
        Run the tool implementation
        Must be overridden by subclasses
        """
        raise NotImplementedError("Tool must implement _run_tool method")
    
    def _save_results(self, result: ToolResult, output_file: str) -> None:
        """Save results to file"""
        try:
            # Create output directory if needed
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save results
            with open(output_path, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

    def log_message(self, level: str, message: str, context: Optional[Dict] = None):
        """Unified logging that respects framework mode"""
        if self.framework_mode:
            if level == "error":
                self._result.add_error(message, context)
            elif level == "warning":
                self._result.add_warning(message, context)
            else:
                self._result.add_message(message, level, context)
        else:
            if level == "error":
                self.logger.error(message)
            elif level == "warning":
                self.logger.warning(message)
            else:
                self.logger.info(message)

    def save_results(self, output_file: str) -> Dict[str, Any]:
        """Save results to a file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Update final status if not already set
            if self._result.status == "initialized":
                self._result.status = "completed"
            
            # Set end time if not set
            if not self._result.end_time:
                self._result.end_time = datetime.now().isoformat()
            
            # Convert to dictionary
            results_dict = self._result.to_dict()
            
            # Save to file
            with open(output_path, 'w') as f:
                json.dump(results_dict, f, indent=4)
            
            self.log_message("info", f"Results saved to {output_file}")
            
            return results_dict
            
        except Exception as e:
            error_msg = f"Error saving results: {str(e)}"
            self.log_message("error", error_msg)
            return {
                "status": "error",
                "error": error_msg
            }

    def generate_html_report(self, output_file: str):
        """Generate an HTML report from the results"""
        try:
            # Basic HTML template
            template_str = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>{{ tool_name }} Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
                    .section { margin: 20px 0; }
                    .finding { border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }
                    .Critical { border-left: 5px solid #ff0000; }
                    .High { border-left: 5px solid #ff6600; }
                    .Medium { border-left: 5px solid #ffcc00; }
                    .Low { border-left: 5px solid #00cc00; }
                    .Info { border-left: 5px solid #0066cc; }
                    .error { color: #ff0000; }
                    .warning { color: #ff6600; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{{ tool_name }} Report</h1>
                    <p>Generated: {{ result.end_time }}</p>
                </div>
                
                <div class="section">
                    <h2>Risk Summary</h2>
                    <ul>
                    {% for level, count in result.risk_summary.items() %}
                        <li>{{ level }}: {{ count }}</li>
                    {% endfor %}
                    </ul>
                </div>
                
                {% if result.errors %}
                <div class="section">
                    <h2>Errors</h2>
                    {% for error in result.errors %}
                        <div class="error">
                            <p>{{ error.message }}</p>
                            <small>{{ error.timestamp }}</small>
                        </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                {% if result.warnings %}
                <div class="section">
                    <h2>Warnings</h2>
                    {% for warning in result.warnings %}
                        <div class="warning">
                            <p>{{ warning.message }}</p>
                            <small>{{ warning.timestamp }}</small>
                        </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                {% if result.findings %}
                <div class="section">
                    <h2>Findings</h2>
                    {% for finding in result.findings %}
                        <div class="finding {{ finding.risk_level }}">
                            <h3>{{ finding.title }}</h3>
                            <p><strong>Risk Level:</strong> {{ finding.risk_level }}</p>
                            <p>{{ finding.description }}</p>
                            {% if finding.evidence %}
                            <pre>{{ finding.evidence }}</pre>
                            {% endif %}
                        </div>
                    {% endfor %}
                </div>
                {% endif %}
            </body>
            </html>
            """
            
            # Render template
            template = Template(template_str)
            html_content = template.render(
                tool_name=self.name,
                result=self._result
            )
            
            # Save HTML file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            self.log_message("info", f"HTML report saved to {output_file}")
            
        except Exception as e:
            self.log_message("error", f"Error generating HTML report: {str(e)}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type is not None:
            self.log_message("error", str(exc_val))
            self._result.status = "error"
        elif self._result.status == "initialized":
            self._result.status = "completed"

class FrameworkTool(BaseTool):
    """Enhanced tool class with improved framework integration"""
    
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
            tool_name=self.name,
            success=True
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