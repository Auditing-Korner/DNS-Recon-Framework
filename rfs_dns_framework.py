#!/usr/bin/env python3

import argparse
import sys
import os
import logging
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich import print as rprint
import importlib.util
from pathlib import Path
from datetime import datetime
import time
import dns.resolver
from jinja2 import Template
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple
from rich.logging import RichHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from tools.utils import check_privileges, check_operation_requirements, elevate_privileges
from rich.text import Text
import rich.traceback

from config_manager import ConfigManager
from tools.base_tool import BaseTool, ToolResult
from tools.registry import registry, list_tools, get_tool, get_tool_config, get_ordered_tools

# Configure rich error handling
rich.traceback.install(show_locals=False)

# Configure logging with improved error handling
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        RichHandler(
            show_time=False,
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
            tracebacks_suppress=[rich.console, rich.table, rich.panel, rich.progress]
        )
    ]
)

# Suppress error output from external libraries
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('azure').setLevel(logging.WARNING)
logging.getLogger('google').setLevel(logging.WARNING)
logging.getLogger('dns').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('paramiko').setLevel(logging.WARNING)
logging.getLogger('scapy.runtime').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Centralized Tool Parameters
TOOL_PARAMETERS = {
    "common": {
        "--domain": {
            "help": "Target domain for analysis",
            "required": False
        },
        "--output": {
            "help": "Output file path for results",
            "required": False
        },
        "--html-report": {
            "help": "Path for HTML report output",
            "required": False
        },
        "--quiet": {
            "help": "Suppress non-essential output",
            "action": "store_true",
            "required": False
        },
        "--verbose": {
            "help": "Enable detailed output",
            "action": "store_true",
            "required": False
        },
        "--timeout": {
            "help": "Operation timeout in seconds",
            "type": int,
            "default": 30,
            "required": False
        },
        "--nameserver": {
            "help": "Custom DNS nameserver to use",
            "required": False
        },
        "--format": {
            "help": "Output format (json, csv, text)",
            "choices": ["json", "csv", "text"],
            "default": "json",
            "required": False
        },
        "--framework-mode": {
            "help": "Run in framework integration mode",
            "action": "store_true",
            "required": False
        }
    },
    
    # DNS tool parameters
    "dns": {
        "--record-types": {
            "help": "DNS record types to query (comma-separated)",
            "default": "A,AAAA,CNAME,MX,NS,TXT,SOA",
            "required": False
        },
        "--check-dnssec": {
            "help": "Enable DNSSEC validation",
            "action": "store_true",
            "required": False
        },
        "--check-wildcards": {
            "help": "Check for wildcard DNS records",
            "action": "store_true",
            "required": False
        },
        "--wordlist": {
            "help": "Path to wordlist file",
            "required": False
        },
        "--concurrent": {
            "help": "Number of concurrent operations",
            "type": int,
            "default": 10,
            "required": False
        }
    },
    
    # Server parameters
    "server": {
        "--server-types": {
            "help": "Types of servers to find",
            "choices": ["authoritative", "recursive", "all"],
            "default": "all",
            "required": False
        },
        "--check-version": {
            "help": "Attempt to determine server versions",
            "action": "store_true",
            "required": False
        },
        "--ports": {
            "help": "Ports to scan (comma-separated)",
            "default": "53,853,5353",
            "required": False
        }
    },
    
    # Cloud parameters
    "cloud": {
        "--providers": {
            "help": "Cloud providers to check",
            "choices": ["aws", "azure", "gcp", "all"],
            "default": "all",
            "required": False
        },
        "--services": {
            "help": "Services to enumerate (comma-separated)",
            "default": "all",
            "required": False
        },
        "--regions": {
            "help": "Regions to check (comma-separated)",
            "default": "all",
            "required": False
        }
    },
    
    # Security parameters
    "security": {
        "--risk-level": {
            "help": "Minimum risk level to report",
            "choices": ["low", "medium", "high", "critical"],
            "default": "low",
            "required": False
        },
        "--verify": {
            "help": "Verify findings",
            "action": "store_true",
            "required": False
        },
        "--include-passive": {
            "help": "Include passive checks",
            "action": "store_true",
            "required": False
        }
    },
    
    # SSL/TLS parameters
    "ssl": {
        "--ssl-ports": {
            "help": "Ports to scan for SSL/TLS",
            "default": "443,8443",
            "required": False
        },
        "--min-tls-version": {
            "help": "Minimum acceptable TLS version",
            "choices": ["1.0", "1.1", "1.2", "1.3"],
            "default": "1.2",
            "required": False
        },
        "--check-ciphers": {
            "help": "Check supported cipher suites",
            "action": "store_true",
            "required": False
        },
        "--check-cert": {
            "help": "Perform certificate validation",
            "action": "store_true",
            "required": False
        }
    }
}

# Framework-specific parameters
FRAMEWORK_PARAMETERS = {
    "--list-tools": {
        "help": "List available tools",
        "action": "store_true"
    },
    "--workflow": {
        "help": "Run complete DNS analysis workflow",
        "action": "store_true"
    },
    "--report-format": {
        "help": "Report format (default: both)",
        "choices": ["json", "html", "both"],
        "default": "both"
    },
    "--check-deps": {
        "help": "Check tool dependencies",
        "action": "store_true"
    },
    "--force": {
        "help": "Try to run operations even without required privileges",
        "action": "store_true"
    },
    "--no-html": {
        "help": "Disable HTML report generation",
        "action": "store_true"
    }
}

class RFSDNSFramework:
    """Main framework class for RFS DNS Framework"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.console = Console()
        self.config = ConfigManager(config_file if config_file else "config.yaml")
        self.setup_logging()
        self.cached_nameservers = {}
        self.tools_dir = Path('tools')
        self.results_dir = Path('results')
        self.version = "2.1.0"
        self.tools = {}
        self.tools_loaded = False
        
        # Initialize workflow results
        self.workflow_results = {
            'timestamp': datetime.now().isoformat(),
            'framework_version': self.version,
            'tools': {},
            'summary': {
                'total_tools': 0,
                'successful_tools': 0,
                'failed_tools': 0,
                'warnings': 0,
                'critical_findings': 0,
                'risk_summary': {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                }
            }
        }

        # Ensure tools directory exists
        if not self.tools_dir.exists():
            self.logger.error(f"Tools directory not found: {self.tools_dir}")
            return

        # Load tools
        self._load_tools()

    def setup_logging(self) -> None:
        """Setup logging configuration"""
        log_level = self.config.get("logging", "level", "INFO")
        console_output = self.config.get("logging", "console_output", True)
        
        logging.basicConfig(
            level=log_level,
            format="%(message)s",
            handlers=[RichHandler()] if console_output else []
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("RFS DNS Framework initialized")

    def _load_tools(self):
        """Load all tool modules from the tools directory"""
        if self.tools_loaded:
            return

        try:
            # Initialize tool registry
            registry.discover_tools(str(self.tools_dir))
            
            # Get all available tools
            self.tools = {}
            for tool_info in list_tools():
                name = tool_info['name']
                module = get_tool(name)
                config = get_tool_config(name)
                
                if module and config:
                    # Define tool-specific argument handling
                    def get_workflow_args(tool_name):
                        """Get the appropriate arguments for a tool in workflow mode"""
                        def workflow_args(domain, output, **kwargs):
                            # Base arguments that all tools should receive
                            args_dict = {
                                'domain': domain,
                                'output': output,
                                'framework_mode': True
                            }
                            
                            # Add tool-specific arguments based on tool type
                            if tool_name in ['dns_enum', 'tld_brute', 'zone_walker']:
                                args_dict.update({
                                    'record_types': 'A,AAAA,CNAME,MX,NS,TXT,SOA',
                                    'check_dnssec': True,
                                    'check_wildcards': True
                                })
                            elif tool_name in ['find_server']:
                                args_dict.update({
                                    'server_types': 'all',
                                    'check_version': True
                                })
                            elif tool_name in ['cloud_enum']:
                                args_dict.update({
                                    'providers': 'all',
                                    'services': 'all'
                                })
                            elif tool_name in ['takeover', 'dns_takeover']:
                                args_dict.update({
                                    'verify': True,
                                    'include_passive': True
                                })
                            elif tool_name in ['ssl_scanner']:
                                args_dict.update({
                                    'ssl_ports': '443,8443',
                                    'check_cert': True,
                                    'check_ciphers': True
                                })
                            
                            # Add any extra arguments from kwargs
                            if kwargs.get('extra_args'):
                                args_dict.update(kwargs['extra_args'])
                            
                            return args_dict
                        return workflow_args

                    self.tools[name] = {
                        'module': module,
                        'description': config['description'],
                        'critical': config['critical'],
                        'requires_root': config['requires_root'],
                        'order': config['order'],
                        'file': config['file'],
                        'workflow_args': get_workflow_args(name)
                    }
                    self.logger.info(f"Loaded {name}")
                else:
                    self.logger.warning(f"Tool {name} not properly configured")
            
        except Exception as e:
            self.logger.error(f"Error loading tools: {e}")
            raise
        
        self.tools_loaded = True

    def display_banner(self):
        """Display framework banner"""
        banner = Text()
        banner.append("╔══════════════════════════════════════════════════════════════════╗\n", style="blue")
        banner.append("║                   ", style="blue")
        banner.append("RFS DNS Framework", style="bold cyan")
        banner.append(f" v{self.version}", style="yellow")
        banner.append("                    ║\n", style="blue")
        banner.append("║              Comprehensive DNS Security Testing                   ║\n", style="blue")
        banner.append("╠══════════════════════════════════════════════════════════════════╣\n", style="blue")
        banner.append("║ ", style="blue")
        banner.append("• Multi-Cloud Security Analysis", style="green")
        banner.append("                                  ║\n", style="blue")
        banner.append("║ ", style="blue")
        banner.append("• Advanced DNS Enumeration & Testing", style="green")
        banner.append("                            ║\n", style="blue")
        banner.append("║ ", style="blue")
        banner.append("• Vulnerability Assessment & Reporting", style="green")
        banner.append("                          ║\n", style="blue")
        banner.append("╠══════════════════════════════════════════════════════════════════╣\n", style="blue")
        banner.append("║ ", style="blue")
        banner.append("Author: ", style="dim white")
        banner.append("rfs85", style="green")
        banner.append("                                                    ║\n", style="blue")
        banner.append("║ ", style="blue")
        banner.append("GitHub: ", style="dim white")
        banner.append("https://github.com/rfs85/RFS-DNS-Framework", style="cyan")
        banner.append("        ║\n", style="blue")
        banner.append("╚══════════════════════════════════════════════════════════════════╝", style="blue")

        self.console.print(banner)

    def list_tools(self):
        """Display available tools with enhanced information"""
        table = Table(
            title="Available Tools",
            title_style="bold magenta",
            show_header=True,
            header_style="bold cyan"
        )
        table.add_column("Tool", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Critical", style="red")
        table.add_column("Order", style="blue")
        
        for tool_info in registry.list_tools():
            status = "[green]Available" if tool_info['loaded'] else "[red]Not Found"
            critical = "[red]Yes" if tool_info['critical'] else "[blue]No"
            order = str(tool_info['order'])
            table.add_row(
                tool_info['name'],
                tool_info['description'],
                status,
                critical,
                order
            )
        
        self.console.print(table)

    def check_tool_requirements(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """Check if the current user has sufficient privileges to run a tool"""
        tool = self.tools.get(tool_name)
        if not tool:
            return False, f"Tool '{tool_name}' not found"
            
        # Check if tool requires root
        if tool.get('requires_root', False):
            has_privs, priv_type = check_privileges()
            if not has_privs:
                return False, f"This tool requires {priv_type}"
                
        # Check specific operation requirements
        for operation in tool.get('operations', []):
            has_privs, error_msg = check_operation_requirements(operation)
            if not has_privs:
                return False, error_msg
                
        return True, None

    def run_tool(self, tool_name: str, tool_args: Dict[str, Any], force: bool = False) -> bool:
        """Run a specific tool with arguments"""
        try:
            # Check tool requirements
            can_run, error_msg = self.check_tool_requirements(tool_name)
            if not can_run and not force:
                self.console.print(f"[red]Error: {error_msg}")
                self.console.print("[yellow]You can use --force to try running anyway, but it might fail")
                return False
            
            # Get the tool info
            tool_info = self.tools.get(tool_name)
            if not tool_info:
                self.console.print(f"[red]Error: Tool '{tool_name}' not found")
                return False
            
            # Get the module
            module = tool_info.get('module')
            if not module:
                self.console.print(f"[red]Error: Tool '{tool_name}' module not loaded")
                return False
            
            # Create tool instance
            if hasattr(module, 'main'):
                # Get workflow arguments for the tool
                workflow_args_func = tool_info['workflow_args']
                if workflow_args_func:
                    # Get the domain and output from tool_args
                    domain = tool_args.get('domain')
                    output = tool_args.get('output', os.path.join('results', domain if domain else '', f"{tool_name}_results.json"))
                    
                    # Get the workflow-specific arguments
                    args_list = workflow_args_func(domain=domain, output=output)
                    
                    # Convert args list to dictionary
                    args_dict = {}
                    i = 0
                    while i < len(args_list):
                        if args_list[i].startswith('--'):
                            key = args_list[i][2:].replace('-', '_')  # Convert --arg-name to arg_name
                            if i + 1 < len(args_list) and not args_list[i + 1].startswith('--'):
                                args_dict[key] = args_list[i + 1]
                                i += 2
                            else:
                                args_dict[key] = True  # Flag argument
                                i += 1
                        else:
                            i += 1
                    
                    # Update with any additional arguments from tool_args
                    args_dict.update(tool_args)
                    
                    # Run the tool with the converted arguments
                    result = module.main()
                    
                    # Handle tool result
                    if isinstance(result, dict):
                        if result.get('status') == 'error':
                            self.console.print(f"[red]Error: {result.get('error')}")
                            return False
                        
                        # Update workflow results
                        if 'risk_summary' in result:
                            for level, count in result['risk_summary'].items():
                                self.workflow_results['summary']['risk_summary'][level] += count
                                if level == 'Critical':
                                    self.workflow_results['summary']['critical_findings'] += count
                        
                        return True
                    return True
                else:
                    self.console.print(f"[red]Error: Tool '{tool_name}' has no workflow arguments configured")
                    return False
            else:
                self.console.print(f"[red]Error: Tool '{tool_name}' has no main() function")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error running tool '{tool_name}': {e}")
            return False

    def detect_nameservers(self, domain: str) -> list:
        """Detect nameservers for a domain"""
        if domain in self.cached_nameservers:
            return self.cached_nameservers[domain]

        try:
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(domain, 'NS')
            nameservers = []
            
            for record in ns_records:
                ns_hostname = str(record.target).rstrip('.')
                try:
                    # Get IP for nameserver
                    answers = resolver.resolve(ns_hostname, 'A')
                    for answer in answers:
                        nameservers.append(str(answer))
                except:
                    continue
            
            if nameservers:
                self.cached_nameservers[domain] = nameservers
                return nameservers
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not detect nameservers: {e}")
        
        # Fallback to common public DNS servers
        return ['8.8.8.8', '1.1.1.1']

    def generate_html_report(self, results: Dict[str, Any], output_file: str) -> None:
        """Generate an HTML report from the results"""
        try:
            template = Template('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RFS DNS Framework Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --success-color: #2ecc71;
            --warning-color: #f1c40f;
            --danger-color: #e74c3c;
            --critical-color: #c0392b;
            --text-color: #2c3e50;
            --background-color: #ecf0f1;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            margin: 0;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        h1, h2, h3 {
            color: var(--primary-color);
            margin-top: 0;
        }
        
        .header {
            background: var(--primary-color);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: white;
            margin: 0;
        }
        
        .timestamp {
            color: rgba(255,255,255,0.8);
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        .summary-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .metric-card h3 {
            margin: 0;
            font-size: 1.1em;
            color: var(--secondary-color);
        }
        
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .findings-section {
            margin-top: 30px;
        }
        
        .finding-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .risk-badge {
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
            color: white;
        }
        
        .risk-Critical { background-color: var(--critical-color); }
        .risk-High { background-color: var(--danger-color); }
        .risk-Medium { background-color: var(--warning-color); color: var(--text-color); }
        .risk-Low { background-color: var(--success-color); }
        
        .details-section {
            background: var(--background-color);
            padding: 15px;
            border-radius: 4px;
            margin-top: 10px;
        }
        
        .details-section pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .tool-section {
            margin-top: 30px;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .error-section {
            margin-top: 30px;
            padding: 20px;
            background: #fee;
            border-radius: 8px;
            border: 1px solid var(--danger-color);
        }
        
        .warning-section {
            margin-top: 30px;
            padding: 20px;
            background: #ffd;
            border-radius: 8px;
            border: 1px solid var(--warning-color);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RFS DNS Framework Report</h1>
            <div class="timestamp">Generated on {{ timestamp }}</div>
        </div>
        
        <div class="summary-dashboard">
            {% if results.summary %}
            <div class="metric-card">
                <h3>Critical Findings</h3>
                <div class="metric-value" style="color: var(--critical-color)">
                    {{ results.summary.risk_summary.Critical|default(0) }}
                </div>
            </div>
            <div class="metric-card">
                <h3>High Risk Findings</h3>
                <div class="metric-value" style="color: var(--danger-color)">
                    {{ results.summary.risk_summary.High|default(0) }}
                </div>
            </div>
            <div class="metric-card">
                <h3>Medium Risk Findings</h3>
                <div class="metric-value" style="color: var(--warning-color)">
                    {{ results.summary.risk_summary.Medium|default(0) }}
                </div>
            </div>
            <div class="metric-card">
                <h3>Low Risk Findings</h3>
                <div class="metric-value" style="color: var(--success-color)">
                    {{ results.summary.risk_summary.Low|default(0) }}
                </div>
            </div>
            {% endif %}
        </div>
        
        {% if results.findings %}
        <div class="findings-section">
            <h2>Findings</h2>
            {% for finding in results.findings %}
            <div class="finding-card">
                <div class="finding-header">
                    <h3>{{ finding.title }}</h3>
                    <span class="risk-badge risk-{{ finding.risk_level }}">{{ finding.risk_level }}</span>
                </div>
                <p>{{ finding.description }}</p>
                {% if finding.details %}
                <div class="details-section">
                    <pre>{{ finding.details|tojson(indent=2) }}</pre>
                </div>
                {% endif %}
                {% if finding.recommendations %}
                <h4>Recommendations</h4>
                <ul>
                    {% for rec in finding.recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if results.tools %}
        {% for tool_name, tool_results in results.tools.items() %}
        <div class="tool-section">
            <h2>{{ tool_name }}</h2>
            <pre>{{ tool_results|tojson(indent=2) }}</pre>
        </div>
        {% endfor %}
        {% endif %}
        
        {% if results.errors %}
        <div class="error-section">
            <h2>Errors</h2>
            <ul>
            {% for error in results.errors %}
                <li>{{ error }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if results.warnings %}
        <div class="warning-section">
            <h2>Warnings</h2>
            <ul>
            {% for warning in results.warnings %}
                <li>{{ warning }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>
</body>
</html>
            ''')
            
            # Generate timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Render template
            html_content = template.render(
                results=results,
                timestamp=timestamp
            )
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Write HTML file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            if not self.args.get('quiet'):
                self.console.print(f"[green]HTML report generated: {output_file}")
        
        except Exception as e:
            self.console.print(f"[red]Error generating HTML report: {str(e)}")
            raise

    def run_workflow(self, domain: str, output_dir: str, report_format: str = "json", force: bool = False):
        """
        Run the complete DNS analysis workflow.
        
        Args:
            domain: Target domain
            output_dir: Output directory for results
            report_format: Report format (json/html)
            force: Force execution even with insufficient privileges
        """
        start_time = datetime.now()
        workflow_summary = {
            'domain': domain,
            'start_time': start_time.isoformat(),
            'tools': {},
            'findings': [],
            'errors': [],
            'warnings': [],
            'risk_summary': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            }
        }
        
        # Create output directory structure
        domain_dir = os.path.join(output_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)
        
        # Get ordered list of tools to run
        ordered_tools = get_ordered_tools()
        total_tools = len(ordered_tools)
        completed_tools = 0
        failed_tools = 0
        
        with Progress() as progress:
            task = progress.add_task("Running workflow...", total=total_tools)
            
            for tool_name, tool_config in ordered_tools:
                try:
                    # Create tool-specific output directory
                    tool_dir = os.path.join(domain_dir, tool_name)
                    os.makedirs(tool_dir, exist_ok=True)
                    
                    # Check tool requirements
                    can_run, error_msg = self.check_tool_requirements(tool_name)
                    if not can_run and not force:
                        workflow_summary['warnings'].append(f"Skipping {tool_name}: {error_msg}")
                        continue
                    
                    # Prepare tool arguments
                    tool_args = {
                        'domain': domain,
                        'output': os.path.join(tool_dir, f"{tool_name}_results.json"),
                        'framework_mode': True
                    }
                    
                    # Add tool-specific parameters from config
                    if tool_name in self.config.get('tool_params', {}):
                        tool_args.update(self.config['tool_params'][tool_name])
                    
                    # Run the tool
                    logging.info(f"Running {tool_name}...")
                    success = self.run_tool(tool_name, tool_args, force)
                    
                    if success:
                        completed_tools += 1
                        # Process tool results
                        result_file = tool_args['output']
                        if os.path.exists(result_file):
                            with open(result_file) as f:
                                result_data = json.load(f)
                                
                            # Update workflow summary
                            workflow_summary['tools'][tool_name] = {
                                'status': 'completed',
                                'findings': len(result_data.get('findings', [])),
                                'errors': result_data.get('errors', []),
                                'warnings': result_data.get('warnings', [])
                            }
                            
                            # Aggregate findings and update risk summary
                            for finding in result_data.get('findings', []):
                                workflow_summary['findings'].append({
                                    'tool': tool_name,
                                    'title': finding.get('title', ''),
                                    'risk_level': finding.get('risk_level', 'Info'),
                                    'description': finding.get('description', '')
                                })
                                
                                risk_level = finding.get('risk_level', 'Info')
                                if risk_level in workflow_summary['risk_summary']:
                                    workflow_summary['risk_summary'][risk_level] += 1
                    else:
                        failed_tools += 1
                        workflow_summary['tools'][tool_name] = {
                            'status': 'failed',
                            'errors': [f"Tool execution failed"]
                        }
                        
                except Exception as e:
                    failed_tools += 1
                    error_msg = f"Error running {tool_name}: {str(e)}"
                    logging.error(error_msg)
                    workflow_summary['errors'].append(error_msg)
                    workflow_summary['tools'][tool_name] = {
                        'status': 'error',
                        'errors': [str(e)]
                    }
                
                finally:
                    progress.update(task, advance=1)
        
        # Complete workflow summary
        end_time = datetime.now()
        workflow_summary.update({
            'end_time': end_time.isoformat(),
            'duration': str(end_time - start_time),
            'total_tools': total_tools,
            'completed_tools': completed_tools,
            'failed_tools': failed_tools,
            'completion_rate': f"{(completed_tools/total_tools)*100:.1f}%"
        })
        
        # Save workflow summary
        summary_file = os.path.join(domain_dir, 'workflow_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(workflow_summary, f, indent=4)
        
        # Generate report if requested
        if report_format == 'html':
            report_file = os.path.join(domain_dir, 'report.html')
            self.generate_html_report(workflow_summary, report_file)
        
        # Display workflow summary
        self.display_workflow_summary(workflow_summary)
        
        return workflow_summary

    def display_workflow_summary(self, summary: Dict[str, Any]):
        """Display workflow execution summary."""
        console = Console()
        
        # Create header
        console.print("\n")
        console.print(Panel.fit(
            "[bold]RFS DNS Framework[/bold]\n"
            f"DNS Analysis Results for {summary['domain']}\n"
            f"Framework Version: {self.version}",
            title="RFS DNS Framework",
            border_style="blue"
        ))
        console.print("\n")
        
        # Create scan summary table
        scan_table = Table(title="Scan Summary", show_header=True)
        scan_table.add_column("Metric", style="cyan")
        scan_table.add_column("Value", justify="right")
        scan_table.add_column("Details", justify="left")
        
        scan_table.add_row(
            "Total Tools",
            str(summary['total_tools']),
            ""
        )
        scan_table.add_row(
            "Successful",
            str(summary['completed_tools']),
            f"{summary['completion_rate']} completion rate"
        )
        scan_table.add_row(
            "Failed",
            str(summary['failed_tools']),
            f"{(summary['failed_tools']/summary['total_tools'])*100:.1f}% failure rate"
        )
        scan_table.add_row(
            "Critical Findings",
            str(summary['risk_summary']['Critical']),
            "No critical issues" if summary['risk_summary']['Critical'] == 0 else "Review required"
        )
        
        console.print(scan_table)
        console.print("\n")
        
        # Create risk analysis table
        risk_table = Table(title="Risk Analysis", show_header=True)
        risk_table.add_column("Risk Level", style="cyan")
        risk_table.add_column("Count", justify="right")
        risk_table.add_column("Percentage", justify="right")
        
        total_findings = sum(summary['risk_summary'].values())
        for level, count in summary['risk_summary'].items():
            percentage = (count/total_findings)*100 if total_findings > 0 else 0
            risk_table.add_row(
                level,
                str(count),
                f"{percentage:.1f}%"
            )
        
        console.print(risk_table)
        console.print("\n")
        
        # Display execution time
        time_panel = Panel(
            f"Start Time: {summary['start_time'].split('.')[0]}\n"
            f"End Time: {summary['end_time'].split('.')[0]}\n"
            f"Duration: {summary['duration']}",
            title="Execution Time",
            border_style="blue"
        )
        console.print(time_panel)

def get_tool_parameters(tool_name: str) -> Dict[str, Any]:
    """Get parameters for a specific tool based on its type and requirements"""
    tool_config = registry.get_tool_config(tool_name)
    if not tool_config:
        return {}
        
    params = {}
    
    # Add common parameters
    params.update(TOOL_PARAMETERS['common'])
    
    # Add tool-specific parameters based on tool type
    if tool_name in ['dns_enum', 'tld_brute', 'zone_walker']:
        params.update(TOOL_PARAMETERS['dns'])
    elif tool_name in ['find_server']:
        params.update(TOOL_PARAMETERS['server'])
    elif tool_name in ['cloud_enum']:
        params.update(TOOL_PARAMETERS['cloud'])
    elif tool_name in ['takeover', 'dns_takeover', 'cache_poison']:
        params.update(TOOL_PARAMETERS['security'])
    elif tool_name in ['ssl_scanner']:
        params.update(TOOL_PARAMETERS['ssl'])
    
    return params

def create_argument_parser():
    """Create and configure the argument parser with all tool parameters"""
    parser = argparse.ArgumentParser(
        description="RFS DNS Framework - A comprehensive DNS reconnaissance and security assessment framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Framework-level arguments
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--list-tools', action='store_true', help='List available tools')
    parser.add_argument('--workflow', action='store_true', help='Run the full workflow')
    parser.add_argument('--force', action='store_true', help='Force run even if requirements not met')
    
    # Add common parameters
    for param, config in TOOL_PARAMETERS['common'].items():
        param_name = param.lstrip('-')
        if 'action' in config:
            parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})
        else:
            parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})

    # Create subparsers for tools
    subparsers = parser.add_subparsers(dest='tool', help='Tool to run')
    
    # Add tool-specific subparsers
    for tool_info in list_tools():
        tool_name = tool_info['name']
        tool_parser = subparsers.add_parser(
            tool_name,
            help=tool_info['description'],
            description=tool_info['description']
        )
        
        # Get tool-specific parameters
        tool_params = get_tool_parameters(tool_name)
        
        # Add parameters to tool parser
        for param, config in tool_params.items():
            param_name = param.lstrip('-')
            if 'action' in config:
                tool_parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})
            else:
                tool_parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})

    return parser

def main():
    """Main entry point for the RFS DNS Framework"""
    try:
        # Initialize framework
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Initialize framework with config
        framework = RFSDNSFramework(config_file=args.config)
        framework.display_banner()

        # Handle --list-tools
        if args.list_tools:
            framework.list_tools()
            return 0

        # Validate domain for workflow or tool execution
        if args.workflow or args.tool:
            if not args.domain:
                parser.error("--domain is required for workflow or tool execution")

        # Handle workflow execution
        if args.workflow:
            output_dir = args.output if args.output else os.path.join('results', args.domain)
            report_format = args.format if hasattr(args, 'format') else 'json'
            framework.run_workflow(args.domain, output_dir, report_format, args.force)
            return 0

        # Handle individual tool execution
        if args.tool:
            # Convert args to dict for tool execution
            tool_args = vars(args)
            
            # Run the selected tool
            success = framework.run_tool(args.tool, tool_args, args.force)
            return 0 if success else 1

        # If no action specified, show help
        parser.print_help()
        return 0

    except KeyboardInterrupt:
        logger.warning("\nOperation interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            logger.exception("Detailed error information:")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 