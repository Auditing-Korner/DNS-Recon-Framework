#!/usr/bin/env python3

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console
import argparse
from jinja2 import Template

class ToolResult:
    """Standardized result object for all tools"""
    def __init__(self):
        self.status: str = "initialized"
        self.start_time: str = datetime.now().isoformat()
        self.end_time: Optional[str] = None
        self.errors: List[Dict[str, str]] = []
        self.warnings: List[Dict[str, str]] = []
        self.messages: List[Dict[str, str]] = []
        self.findings: List[Dict[str, Any]] = []
        self.risk_summary: Dict[str, int] = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        self.metadata: Dict[str, Any] = {}

    def add_error(self, message: str, context: Optional[Dict] = None):
        """Add an error message with optional context"""
        self.errors.append({
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        })

    def add_warning(self, message: str, context: Optional[Dict] = None):
        """Add a warning message with optional context"""
        self.warnings.append({
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        })

    def add_message(self, message: str, level: str = "info", context: Optional[Dict] = None):
        """Add an informational message with optional context"""
        self.messages.append({
            "message": message,
            "level": level,
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        })

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding with risk level"""
        self.findings.append(finding)
        risk_level = finding.get("risk_level", "Info")
        self.risk_summary[risk_level] = self.risk_summary.get(risk_level, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format"""
        return {
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time or datetime.now().isoformat(),
            "errors": self.errors,
            "warnings": self.warnings,
            "messages": self.messages,
            "findings": self.findings,
            "risk_summary": self.risk_summary,
            "metadata": self.metadata
        }

class BaseTool(ABC):
    """Base class for all tools in the framework"""
    def __init__(self, framework_mode: bool = False):
        self.framework_mode = framework_mode
        self.console = Console()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.result = ToolResult()
        
        # Configure logging
        if not framework_mode:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )

    def log_message(self, level: str, message: str, context: Optional[Dict] = None):
        """Unified logging that respects framework mode"""
        if self.framework_mode:
            if level == "error":
                self.result.add_error(message, context)
            elif level == "warning":
                self.result.add_warning(message, context)
            else:
                self.result.add_message(message, level, context)
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
            if self.result.status == "initialized":
                self.result.status = "completed"
            
            # Set end time if not set
            if not self.result.end_time:
                self.result.end_time = datetime.now().isoformat()
            
            # Convert to dictionary
            results_dict = self.result.to_dict()
            
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
                tool_name=self.__class__.__name__,
                result=self.result
            )
            
            # Save HTML file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            self.log_message("info", f"HTML report saved to {output_file}")
            
        except Exception as e:
            self.log_message("error", f"Error generating HTML report: {str(e)}")

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up command line arguments for the tool"""
        parser.add_argument('domain', help='Target domain')
        parser.add_argument('--output', help='Output file for results (JSON format)')
        parser.add_argument('--html-report', help='Generate HTML report')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Running as part of framework workflow')
        self._add_tool_arguments(parser)

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Execute the tool and handle results"""
        result = self._run_tool(args)
        
        # Save results if output file specified
        if hasattr(args, 'output') and args.output:
            self._save_results(result, args.output, 'json')
            
        # Generate HTML report if specified
        if hasattr(args, 'html_report') and args.html_report:
            self._save_results(result, args.html_report, 'html')
            
        return result

    def _save_results(self, result: ToolResult, filepath: str, format: str) -> None:
        """Save results to file in specified format"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            if format == 'json':
                with open(filepath, 'w') as f:
                    json.dump(result.to_dict(), f, indent=2)
            elif format == 'html':
                self._generate_html_report(result, filepath)
                
        except Exception as e:
            self.log_message('error', f"Error saving results: {str(e)}")

    def _generate_html_report(self, result: ToolResult, filepath: str) -> None:
        """Generate HTML report with improved styling"""
        try:
            template_str = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>{{ tool_name }} Report</title>
                <style>
                    :root {
                        --primary-color: #2c3e50;
                        --secondary-color: #3498db;
                        --success-color: #27ae60;
                        --warning-color: #f39c12;
                        --danger-color: #c0392b;
                        --info-color: #2980b9;
                    }
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        margin: 0;
                        padding: 20px;
                        background: #f5f6fa;
                        color: var(--primary-color);
                    }
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                        background: white;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }
                    .header {
                        text-align: center;
                        padding: 20px;
                        background: var(--primary-color);
                        color: white;
                        border-radius: 8px;
                        margin-bottom: 30px;
                    }
                    .section {
                        margin: 30px 0;
                        padding: 20px;
                        background: #fff;
                        border-radius: 8px;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    }
                    .finding {
                        margin: 15px 0;
                        padding: 15px;
                        border-radius: 6px;
                    }
                    .finding.Critical {
                        background: #fde8e8;
                        border-left: 4px solid var(--danger-color);
                    }
                    .finding.High {
                        background: #fef3c7;
                        border-left: 4px solid var(--warning-color);
                    }
                    .finding.Medium {
                        background: #e8f4fd;
                        border-left: 4px solid var(--info-color);
                    }
                    .finding.Low {
                        background: #e8f8f0;
                        border-left: 4px solid var(--success-color);
                    }
                    .summary-box {
                        display: inline-block;
                        padding: 15px;
                        margin: 10px;
                        border-radius: 6px;
                        min-width: 150px;
                        text-align: center;
                    }
                    .evidence {
                        background: #f8fafc;
                        padding: 10px;
                        border-radius: 4px;
                        font-family: monospace;
                        margin: 10px 0;
                    }
                    h1, h2, h3 {
                        color: var(--primary-color);
                    }
                    .timestamp {
                        color: #666;
                        font-size: 0.9em;
                        text-align: right;
                        margin-top: 20px;
                    }
                    .risk-summary {
                        display: flex;
                        justify-content: space-around;
                        flex-wrap: wrap;
                        margin: 20px 0;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>{{ tool_name }}</h1>
                        <p>Security Analysis Report</p>
                    </div>
                    
                    <div class="section">
                        <h2>Overview</h2>
                        <div class="risk-summary">
                            {% for level, count in result.risk_summary.items() %}
                            <div class="summary-box {{ level }}">
                                <h3>{{ level }}</h3>
                                <p>{{ count }}</p>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    
                    {% if result.findings %}
                    <div class="section">
                        <h2>Findings</h2>
                        {% for finding in result.findings %}
                        <div class="finding {{ finding.risk_level }}">
                            <h3>{{ finding.title }}</h3>
                            <p><strong>Risk Level:</strong> {{ finding.risk_level }}</p>
                            <p>{{ finding.description }}</p>
                            {% if finding.evidence %}
                            <div class="evidence">
                                <pre>{{ finding.evidence }}</pre>
                            </div>
                            {% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    {% if result.errors %}
                    <div class="section">
                        <h2>Errors</h2>
                        {% for error in result.errors %}
                        <div class="finding Critical">
                            <p>{{ error }}</p>
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    {% if result.warnings %}
                    <div class="section">
                        <h2>Warnings</h2>
                        {% for warning in result.warnings %}
                        <div class="finding High">
                            <p>{{ warning }}</p>
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    <div class="timestamp">
                        Generated: {{ result.timestamp }}
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Prepare template data
            template_data = {
                'tool_name': self.__class__.__name__,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            # Render template
            template = Template(template_str)
            html_content = template.render(**template_data)
            
            # Save HTML file
            with open(filepath, 'w') as f:
                f.write(html_content)
                
            self.log_message('info', f"HTML report saved to {filepath}")
            
        except Exception as e:
            self.log_message('error', f"Error generating HTML report: {str(e)}")

    @abstractmethod
    def _run_tool(self, args: argparse.Namespace) -> ToolResult:
        """Main tool implementation to be overridden by subclasses"""
        pass

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type is not None:
            self.log_message("error", str(exc_val))
            self.result.status = "error"
        elif self.result.status == "initialized":
            self.result.status = "completed" 