"""
Base tool class for RFS DNS Framework tools
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
import argparse
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
import logging

@dataclass
class ToolResult:
    """Standard result format for tools"""
    success: bool
    tool_name: str
    findings: List[Dict[str, Any]]
    risk_summary: Dict[str, int] = None
    errors: List[Dict[str, str]] = None
    warnings: List[Dict[str, str]] = None
    messages: List[Dict[str, str]] = None
    raw_output: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    start_time: str = None
    end_time: str = None
    output_file: str = None
    output_dir: str = None

    def __post_init__(self):
        if self.risk_summary is None:
            self.risk_summary = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            }
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.messages is None:
            self.messages = []
        if self.metadata is None:
            self.metadata = {}
        if self.start_time is None:
            self.start_time = datetime.now().isoformat()

    def add_finding(self, title: str, description: str, risk_level: str, evidence: Optional[str] = None):
        """Add a finding with proper risk tracking"""
        finding = {
            "title": title,
            "description": description,
            "risk_level": risk_level,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        if risk_level in self.risk_summary:
            self.risk_summary[risk_level] += 1

    def add_error(self, message: str, context: Optional[Dict] = None):
        """Add an error message"""
        self.errors.append({
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        })

    def add_warning(self, message: str, context: Optional[Dict] = None):
        """Add a warning message"""
        self.warnings.append({
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        })

    def add_message(self, message: str, level: str = "info", context: Optional[Dict] = None):
        """Add an informational message"""
        self.messages.append({
            "message": message,
            "level": level,
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        })

    def finalize(self):
        """Finalize the result before returning"""
        self.end_time = datetime.now().isoformat()

class BaseTool(ABC):
    """Base class for all RFS DNS Framework tools"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.requires_root = False
        self.framework_mode = False
        self.output_file = None
        self.console = Console()
        self.logger = logging.getLogger(self.name)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            handlers=[RichHandler()]
        )
    
    @abstractmethod
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')
        parser.add_argument('--force', action='store_true',
                          help='Try to run without required privileges')
        parser.add_argument('--output', '-o',
                          help='Output file for results')
        parser.add_argument('--format', choices=['json', 'html', 'both'],
                          default='json', help='Output format')
    
    @abstractmethod
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the tool with the given arguments"""
        pass

    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if all required dependencies are available"""
        return True, None

    def save_results(self, results: ToolResult) -> None:
        """Save tool results to file"""
        if self.output_file:
            try:
                output_path = Path(self.output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Finalize results
                results.finalize()
                
                # Save in requested format
                if hasattr(self.args, 'format'):
                    if self.args.format in ['json', 'both']:
                        json_path = output_path.with_suffix('.json')
                        with open(json_path, 'w') as f:
                            json.dump(results.__dict__, f, indent=4)
                            
                    if self.args.format in ['html', 'both']:
                        self.generate_html_report(results, output_path.with_suffix('.html'))
                else:
                    # Default to JSON
                    with open(output_path, 'w') as f:
                        json.dump(results.__dict__, f, indent=4)
                        
            except Exception as e:
                self.logger.error(f"Error saving results: {e}")
    
    def generate_html_report(self, results: ToolResult, output_file: str) -> None:
        """Generate an HTML report from the results"""
        try:
            from jinja2 import Template
            
            # HTML template for tool-specific reports
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
                    <p>Generated: {{ results.end_time }}</p>
                </div>
                
                <div class="section">
                    <h2>Risk Summary</h2>
                    <ul>
                    {% for level, count in results.risk_summary.items() %}
                        <li>{{ level }}: {{ count }}</li>
                    {% endfor %}
                    </ul>
                </div>
                
                {% if results.findings %}
                <div class="section">
                    <h2>Findings</h2>
                    {% for finding in results.findings %}
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
                
                {% if results.errors %}
                <div class="section">
                    <h2>Errors</h2>
                    {% for error in results.errors %}
                        <div class="error">
                            <p>{{ error.message }}</p>
                            <small>{{ error.timestamp }}</small>
                        </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                {% if results.warnings %}
                <div class="section">
                    <h2>Warnings</h2>
                    {% for warning in results.warnings %}
                        <div class="warning">
                            <p>{{ warning.message }}</p>
                            <small>{{ warning.timestamp }}</small>
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
                results=results
            )
            
            # Save HTML file
            with open(output_file, 'w') as f:
                f.write(html_content)
                
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
    
    def main(self) -> Optional[Dict]:
        """Main entry point for the tool"""
        parser = argparse.ArgumentParser(description=self.description)
        self.setup_argparse(parser)
        self.args = parser.parse_args()
        
        # Store common arguments
        self.framework_mode = self.args.framework_mode
        self.output_file = self.args.output
        
        try:
            # Check dependencies
            deps_ok, deps_error = self.check_dependencies()
            if not deps_ok:
                if self.framework_mode:
                    return {
                        "status": "error",
                        "error": f"Dependency check failed: {deps_error}"
                    }
                else:
                    self.logger.error(f"Dependency check failed: {deps_error}")
                    return None
            
            # Run the tool
            results = self.run(self.args)
            
            # Save results if output file specified
            if self.output_file:
                self.save_results(results)
            
            # Return results in framework mode
            if self.framework_mode:
                return results.__dict__
            
            return None
            
        except Exception as e:
            error_msg = str(e)
            if self.framework_mode:
                return {
                    "status": "error",
                    "error": error_msg
                }
            else:
                self.logger.error(f"Error: {error_msg}")
                return None 