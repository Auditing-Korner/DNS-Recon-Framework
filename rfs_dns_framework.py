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
from tools import registry

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
        }
    },
    
    "dns_enum": {
        "description": "DNS Enumeration Tool",
        "requires_root": False,
        "critical": True,
        "order": 1,
        "parameters": {
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
                "help": "Path to subdomain wordlist",
                "required": False
            }
        }
    },
    
    "find_server": {
        "description": "DNS Server Discovery Tool",
        "requires_root": False,
        "critical": True,
        "order": 2,
        "parameters": {
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
            }
        }
    },
    
    "cloud_enum": {
        "description": "Cloud Service Enumeration",
        "requires_root": False,
        "critical": True,
        "order": 3,
        "parameters": {
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
            }
        }
    },
    
    "dns_takeover": {
        "description": "DNS Takeover Scanner",
        "requires_root": False,
        "critical": True,
        "order": 4,
        "parameters": {
            "--providers": {
                "help": "Service providers to check",
                "default": "all",
                "required": False
            },
            "--verify-takeover": {
                "help": "Verify potential takeover vulnerabilities",
                "action": "store_true",
                "required": False
            },
            "--include-inactive": {
                "help": "Include inactive/parked domains",
                "action": "store_true",
                "required": False
            }
        }
    },
    
    "mobile_gw": {
        "description": "Mobile Gateway Scanner",
        "requires_root": True,
        "critical": False,
        "order": 5,
        "parameters": {
            "--gateway-type": {
                "help": "Type of mobile gateways to scan",
                "choices": ["sgw", "pgw", "mme", "all"],
                "default": "all",
                "required": False
            },
            "--operator": {
                "help": "Target mobile operator",
                "required": False
            },
            "--mcc": {
                "help": "Mobile Country Code",
                "required": False
            },
            "--mnc": {
                "help": "Mobile Network Code",
                "required": False
            }
        }
    },
    
    "ssl_scanner": {
        "description": "SSL/TLS Security Scanner",
        "requires_root": False,
        "critical": True,
        "order": 6,
        "parameters": {
            "--ports": {
                "help": "Ports to scan (comma-separated)",
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
    },
    
    "cache_poison": {
        "description": "DNS Cache Poisoning Detector",
        "requires_root": True,
        "critical": True,
        "order": 7,
        "parameters": {
            "--test-mode": {
                "help": "Cache poisoning test mode",
                "choices": ["passive", "active", "both"],
                "default": "passive",
                "required": False
            },
            "--query-rate": {
                "help": "Query rate for testing",
                "type": int,
                "default": 100,
                "required": False
            },
            "--randomize-qnames": {
                "help": "Use random query names",
                "action": "store_true",
                "required": False
            }
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
    def __init__(self, config_file: Optional[str] = None):
        self.console = Console()
        self.config = ConfigManager(config_file if config_file else "config.yaml")
        self.setup_logging()
        self.cached_nameservers = {}
        self.tools_dir = Path('tools')
        self.results_dir = Path('results')
        self.version = "2.1.0"
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

        if not self.tools_dir.exists():
            self.console.print(f"[red]Error: Tools directory '{self.tools_dir}' not found")
            return

        try:
            # Get tool information from registry
            self.tools = {}
            for tool_info in registry.list_tools():
                name = tool_info['name']
                module = registry.get_tool(name)
                config = registry.get_tool_config(name)
                
                if module and config:
                    # Define tool-specific argument handling
                    def get_workflow_args(tool_name):
                        """Get the appropriate arguments for a tool in workflow mode"""
                        def workflow_args(domain, output, **kwargs):
                            # Base arguments that all tools should receive
                            base_args = [
                                '--domain', domain,
                                '--output', output,
                                '--framework-mode'
                            ]
                            
                            # Add tool-specific arguments based on tool name
                            if tool_name == 'dns_enum':
                                base_args.extend([
                                    '--record-types', 'A,AAAA,CNAME,MX,NS,TXT,SOA',
                                    '--check-dnssec',
                                    '--check-wildcards'
                                ])
                            elif tool_name == 'find_server':
                                base_args.extend([
                                    '--server-types', 'all',
                                    '--check-version'
                                ])
                            elif tool_name == 'cloud_enum':
                                base_args.extend([
                                    '--provider', 'all',
                                    '--check-dns',
                                    '--check-http'
                                ])
                            elif tool_name == 'tld_brute':
                                base_args.extend([
                                    '--concurrent', '50',
                                    '--check-whois'
                                ])
                            elif tool_name == 'takeover':
                                base_args.extend([
                                    '--providers', 'all',
                                    '--verify-takeover'
                                ])
                            elif tool_name == 'seizure':
                                base_args.extend([
                                    '--check-whois',
                                    '--check-dns',
                                    '--check-http'
                                ])
                            elif tool_name == 'mobile_gw':
                                base_args.extend([
                                    '--gateway-type', 'all',
                                    '--no-protocol-tests'
                                ])
                            elif tool_name == 'cache_poison':
                                base_args.extend([
                                    '--test-mode', 'passive',
                                    '--randomize-qnames'
                                ])
                            elif tool_name == 'ssl_scanner':
                                base_args.extend([
                                    '--ports', '443,8443',
                                    '--check-cert',
                                    '--check-ciphers'
                                ])
                            elif tool_name == 'dns_takeover':
                                base_args.extend([
                                    '--providers', 'all',
                                    '--verify-takeover',
                                    '--include-inactive'
                                ])
                                
                            # Add any extra arguments from kwargs
                            if kwargs.get('extra_args'):
                                base_args.extend(kwargs['extra_args'])
                                    
                            return base_args
                        return workflow_args

                    self.tools[name] = {
                        'module': module,
                        'description': config['description'],
                        'critical': config['critical'],
                        'requires_root': config['requires_root'],
                        'order': config['order'],
                        'script': config['file'],
                        'workflow_args': get_workflow_args(name)
                    }
                    self.console.print(f"[green]Loaded {name}")
                else:
                    self.console.print(f"[yellow]Warning: Tool {name} not properly configured")
            
        except Exception as e:
            self.console.print(f"[red]Error loading tools: {e}")
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
                # Start with the script name
                cmd_args = [tool_info['script']]
                
                # Get workflow arguments for the tool
                workflow_args_func = tool_info['workflow_args']
                if workflow_args_func:
                    # Get the domain and output from tool_args
                    domain = tool_args.get('domain')
                    output = tool_args.get('output', os.path.join('results', domain if domain else '', f"{tool_name}_results.json"))
                    
                    # Get the workflow-specific arguments
                    args_list = workflow_args_func(domain=domain, output=output)
                    cmd_args.extend(args_list)
                
                # Set up sys.argv for the tool
                sys.argv = cmd_args
                
                # Run the tool
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
        """Run a complete DNS analysis workflow"""
        self.console.print(f"[blue]Starting comprehensive DNS analysis for {domain}")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Store workflow metadata
        self.workflow_results.update({
            'domain': domain,
            'output_dir': output_dir,
            'start_time': datetime.now().isoformat(),
            'tools': {}
        })
        
        # Check for root privileges if needed
        has_privs, priv_type = check_privileges()
        if not has_privs:
            if force:
                self.console.print(f"[yellow]Warning: Running without {priv_type} (forced)")
            else:
                self.console.print(f"[yellow]Warning: Running without {priv_type}")
                self.console.print("[yellow]Some features may be limited. Use --force to attempt all operations")
        
        # Get ordered tools from registry
        ordered_tools = registry.get_ordered_tools()
        
        with Progress() as progress:
            total_steps = len(ordered_tools)
            task = progress.add_task("[cyan]Running workflow...", total=total_steps)
            
            # Create thread pool for parallel execution where possible
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_tool = {}
                
                for tool_name, tool_config in ordered_tools:
                    # Skip tools requiring root if we don't have it and not forcing
                    if tool_config.get('requires_root') and not has_privs and not force:
                        self.console.print(f"[yellow]Skipping {tool_name} (requires {priv_type})")
                        continue
                    
                    step_output = os.path.join(output_dir, f"{tool_name}_results.json")
                    step_dir = os.path.join(output_dir, tool_name)
                    
                    self.console.print(f"\n[yellow]Running {tool_config['description']}")
                    
                    try:
                        # Create results directory for this step
                        os.makedirs(step_dir, exist_ok=True)
                        
                        # Get tool-specific arguments
                        extra_args = []
                        
                        # Add nameserver if tool requires it
                        if tool_config.get('requires_nameserver'):
                            nameservers = self.detect_nameservers(domain)
                            if nameservers:
                                extra_args.extend(['--nameserver', nameservers[0]])
                        
                        # Get tool arguments
                        args = self.tools[tool_name]['workflow_args'](
                            domain=domain,
                            output=step_output,
                            extra_args=extra_args
                        )
                        
                        # Submit tool execution to thread pool if it's safe to run in parallel
                        if not tool_config.get('requires_root') and not tool_config.get('sequential'):
                            future = executor.submit(self.run_tool, tool_name, args, force)
                            future_to_tool[future] = (tool_name, tool_config, step_output, step_dir)
                        else:
                            # Run sequentially for tools that require root or need to be run sequentially
                            success = self.run_tool(tool_name, args, force)
                            self._handle_tool_result(tool_name, tool_config, step_output, step_dir, success)
                            progress.update(task, advance=1)
                        
                    except Exception as e:
                        error_msg = f"Error setting up {tool_name}: {str(e)}"
                        self.console.print(f"[red]{error_msg}")
                        self._handle_tool_error(tool_name, tool_config, str(e))
                        progress.update(task, advance=1)
                
                # Process completed parallel tools
                for future in as_completed(future_to_tool):
                    tool_name, tool_config, step_output, step_dir = future_to_tool[future]
                    try:
                        success = future.result()
                        self._handle_tool_result(tool_name, tool_config, step_output, step_dir, success)
                    except Exception as e:
                        error_msg = f"Error in {tool_name}: {str(e)}"
                        self.console.print(f"[red]{error_msg}")
                        self._handle_tool_error(tool_name, tool_config, str(e))
                    
                    progress.update(task, advance=1)
        
        # Update workflow completion time
        self.workflow_results['end_time'] = datetime.now().isoformat()
        
        # Save workflow summary
        summary_file = os.path.join(output_dir, "workflow_summary.json")
        try:
            with open(summary_file, 'w') as f:
                json.dump(self.workflow_results, f, indent=4)
            self.console.print(f"\n[green]Workflow summary saved to {summary_file}")
        except Exception as e:
            self.console.print(f"[red]Error saving workflow summary: {e}")
        
        # Generate reports
        if report_format in ["html", "both"]:
            html_report = os.path.join(output_dir, "report.html")
            self.generate_html_report(self.workflow_results, html_report)
        
        # Display final summary
        self.display_workflow_summary()

    def _handle_tool_result(self, tool_name: str, tool_config: Dict[str, Any], 
                          step_output: str, step_dir: str, success: bool) -> None:
        """Handle the result of a tool execution"""
        tool_result = {
            'success': success,
            'output_file': step_output if success else None,
            'output_dir': step_dir,
            'timestamp': datetime.now().isoformat(),
            'critical': tool_config.get('critical', False)
        }
        
        # Load and merge tool-specific results if available
        if success and os.path.exists(step_output):
            try:
                with open(step_output) as f:
                    tool_data = json.load(f)
                    tool_result.update(tool_data)
                    
                    # Update risk summary
                    if 'risk_summary' in tool_data:
                        for level, count in tool_data['risk_summary'].items():
                            self.workflow_results['summary']['risk_summary'][level] = \
                                self.workflow_results['summary']['risk_summary'].get(level, 0) + count
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not load results for {tool_name}: {e}")
        
        self.workflow_results['tools'][tool_name] = tool_result
        
        # Update summary
        self.workflow_results['summary']['total_tools'] += 1
        if success:
            self.workflow_results['summary']['successful_tools'] += 1
        else:
            self.workflow_results['summary']['failed_tools'] += 1
            if tool_config.get('critical'):
                self.workflow_results['summary']['critical_findings'] += 1

    def _handle_tool_error(self, tool_name: str, tool_config: Dict[str, Any], error: str) -> None:
        """Handle a tool execution error"""
        self.workflow_results['tools'][tool_name] = {
            'success': False,
            'error': error,
            'timestamp': datetime.now().isoformat(),
            'critical': tool_config.get('critical', False)
        }
        self.workflow_results['summary']['failed_tools'] += 1
        if tool_config.get('critical'):
            self.workflow_results['summary']['critical_findings'] += 1

    def display_workflow_summary(self):
        """Display a comprehensive summary of the workflow results"""
        summary = self.workflow_results['summary']
        
        # Create header banner
        header = Panel(
            f"[bold blue]DNS Analysis Results for {self.workflow_results['domain']}[/bold blue]\n"
            f"[cyan]Framework Version:[/cyan] {self.version}\n"
            f"[cyan]Scan Date:[/cyan] {self.workflow_results.get('start_time', 'N/A')}",
            title="RFS DNS Framework",
            title_align="center",
            border_style="blue"
        )
        self.console.print("\n", header)
        
        # Create main summary table with better styling
        table = Table(
            title="Scan Summary",
            title_style="bold magenta",
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
            padding=(0, 2)
        )
        table.add_column("Metric", style="cyan", justify="right")
        table.add_column("Value", style="yellow", justify="left")
        table.add_column("Details", style="green")
        
        # Add summary statistics with improved formatting
        total_tools = summary['total_tools']
        successful = summary['successful_tools']
        failed = summary['failed_tools']
        
        table.add_row(
            "Total Tools",
            str(total_tools),
            ""
        )
        table.add_row(
            "Successful",
            f"[green]{successful}[/green]",
            f"[green]{(successful/total_tools*100):.1f}% completion rate[/green]"
        )
        table.add_row(
            "Failed",
            f"[red]{failed}[/red]",
            f"[red]{(failed/total_tools*100):.1f}% failure rate[/red]"
        )
        table.add_row(
            "Critical Findings",
            f"[red bold]{summary['critical_findings']}[/red bold]",
            "[red]Immediate attention required[/red]" if summary['critical_findings'] > 0 else "[green]No critical issues[/green]"
        )
        
        self.console.print("\n", table)
        
        # Display risk summary
        risk_table = Table(
            title="Risk Analysis",
            title_style="bold red",
            show_header=True,
            header_style="bold white",
            border_style="red"
        )
        risk_table.add_column("Risk Level", style="white")
        risk_table.add_column("Count", justify="center")
        risk_table.add_column("Percentage", justify="right")
        
        total_risks = sum(summary['risk_summary'].values())
        if total_risks > 0:
            for level, count in summary['risk_summary'].items():
                color = {
                    'Critical': 'red',
                    'High': 'orange1',
                    'Medium': 'yellow',
                    'Low': 'green',
                    'Info': 'blue'
                }.get(level, 'white')
                
                percentage = (count / total_risks * 100) if total_risks > 0 else 0
                risk_table.add_row(
                    f"[{color}]{level}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                    f"[{color}]{percentage:.1f}%[/{color}]"
                )
        
        self.console.print("\n", risk_table)
        
        # Display tool-specific results with enhanced formatting
        tool_table = Table(
            title="Tool Results",
            title_style="bold magenta",
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
            padding=(0, 1)
        )
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Status", style="green", justify="center")
        tool_table.add_column("Critical", style="red", justify="center")
        tool_table.add_column("Findings", style="yellow")
        tool_table.add_column("Risk Level", style="magenta")
        
        for tool_name, result in self.workflow_results['tools'].items():
            status = "[green]✓[/green]" if result.get('success') else "[red]✗[/red]"
            critical = "[red]Yes[/red]" if result.get('critical') else "[blue]No[/blue]"
            
            # Extract findings count and risk level
            findings = "N/A"
            risk_level = "[green]Low[/green]"
            
            if 'findings' in result:
                if isinstance(result['findings'], list):
                    findings = str(len(result['findings']))
                    if len(result['findings']) > 0:
                        highest_risk = max((f.get('risk_level', 'Low') for f in result['findings']), default='Low')
                        risk_level = self._format_risk_level(highest_risk)
                elif isinstance(result['findings'], dict):
                    findings = str(sum(result['findings'].values()))
            
            if 'error' in result:
                findings = f"[red]Error: {result['error']}[/red]"
                risk_level = "[red]Error[/red]"
            
            tool_table.add_row(tool_name, status, critical, findings, risk_level)
        
        self.console.print("\n", tool_table)
        
        # Display timing information with better formatting
        if 'start_time' in self.workflow_results and 'end_time' in self.workflow_results:
            start = datetime.fromisoformat(self.workflow_results['start_time'])
            end = datetime.fromisoformat(self.workflow_results['end_time'])
            duration = end - start
            
            time_panel = Panel(
                f"[cyan]Start Time:[/cyan] {start.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"[cyan]End Time:[/cyan] {end.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"[cyan]Duration:[/cyan] {duration}",
                title="Execution Time",
                title_align="center",
                border_style="blue",
                padding=(1, 2)
            )
            self.console.print("\n", time_panel)
        
        # Display recommendations if there are issues
        if summary['critical_findings'] > 0 or summary['failed_tools'] > 0:
            recommendations = []
            
            if summary['critical_findings'] > 0:
                recommendations.append("[red]• Address critical security findings immediately[/red]")
            if summary['failed_tools'] > 0:
                recommendations.append("[yellow]• Investigate and resolve tool failures[/yellow]")
            
            rec_panel = Panel(
                "\n".join(recommendations),
                title="Recommendations",
                title_align="center",
                border_style="yellow",
                padding=(1, 2)
            )
            self.console.print("\n", rec_panel)

    def _format_risk_level(self, risk_level):
        """Format risk level with appropriate color"""
        colors = {
            'Critical': 'red',
            'High': 'orange1',
            'Medium': 'yellow',
            'Low': 'green',
            'Info': 'blue'
        }
        color = colors.get(risk_level, 'white')
        return f"[{color}]{risk_level}[/{color}]"

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
    for tool_name, tool_config in TOOL_PARAMETERS.items():
        if tool_name != 'common':  # Skip common parameters
            tool_parser = subparsers.add_parser(
                tool_name, 
                help=tool_config['description'],
                description=tool_config['description']
            )
            
            # Add common parameters to tool parser
            for param, config in TOOL_PARAMETERS['common'].items():
                param_name = param.lstrip('-')
                if 'action' in config:
                    tool_parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})
                else:
                    tool_parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})
            
            # Add tool-specific parameters
            for param, config in tool_config.get('parameters', {}).items():
                param_name = param.lstrip('-')
                if 'action' in config:
                    tool_parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})
                else:
                    tool_parser.add_argument(param, **{k: v for k, v in config.items() if k != 'required'})

    return parser

def main():
    """Main entry point for the RFS DNS Framework"""
    parser = create_argument_parser()
    args = parser.parse_args()

    try:
        # Initialize framework
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