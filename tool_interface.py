#!/usr/bin/env python3

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console

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
            from jinja2 import Template
            
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

    @abstractmethod
    def run(self, *args, **kwargs):
        """Main method to be implemented by each tool"""
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