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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RFSDNSFramework:
    def __init__(self):
        self.console = Console()
        self.cached_nameservers = {}  # Cache for discovered nameservers
        self.tools = {
            'dns-enum': {
                'script': 'dns_enum.py',
                'description': 'Comprehensive DNS enumeration and analysis',
                'module': None,
                'workflow_args': lambda domain, output: [
                    domain,
                    '--output', output,
                    '--format', 'json',
                    '--verbose'
                ]
            },
            'find-server': {
                'script': 'find_dnsserver.py',
                'description': 'Discover and test DNS servers',
                'module': None,
                'workflow_args': lambda domain, output: [
                    domain,
                    '--top',
                    '--root',
                    '--aws'
                ]
            },
            'cloud-enum': {
                'script': 'enumerate_cloud_providers.py',
                'description': 'Detect and analyze cloud service providers',
                'module': None,
                'workflow_args': lambda domain, output: [
                    '--dns', domain,
                    '--analyze',
                    '--file', 'providers.json'
                ]
            },
            'tld-brute': {
                'script': 'dns_tld_bruteforce.py',
                'description': 'Multi-threaded TLD discovery',
                'module': None,
                'workflow_args': lambda domain, output: [
                    domain.split('.')[0],
                    '--type', 'all',
                    '--timeout', '2',
                    '--threads', '10'
                ]
            },
            'takeover': {
                'script': 'cloud_takeover_detector.py',
                'description': 'Identify subdomain takeover vulnerabilities',
                'module': None,
                'workflow_args': lambda domain, output: [
                    domain,
                    '--output', output,
                    '--threads', '10',
                    '--timeout', '5',
                    '--framework-mode'  # Enable framework integration mode
                ]
            },
            'cache-poison': {
                'script': 'dns_cache_poison.py',
                'description': 'DNS cache poisoning detection and simulation',
                'module': None,
                'requires_nameserver': True,
                'workflow_args': lambda domain, output, nameserver=None: [
                    '--target', domain,
                    '--nameserver', nameserver or '8.8.8.8',  # Fallback to Google DNS
                    '--spoofed-ip', '192.0.2.1',  # Use TEST-NET-1 IP for testing
                    '--mode', 'detect',
                    '--output', output,
                    '--threads', '10'
                ]
            }
        }
        
        # Load tool modules
        self._load_tools()

    def _load_tools(self):
        """Load all tool modules"""
        for tool_name, tool_info in self.tools.items():
            script_path = Path(tool_info['script'])
            if script_path.exists():
                try:
                    spec = importlib.util.spec_from_file_location(
                        tool_name.replace('-', '_'),
                        script_path
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.tools[tool_name]['module'] = module
                except Exception as e:
                    logger.error(f"Error loading {tool_name}: {e}")

    def display_banner(self):
        """Display framework banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                    RFS DNS Framework v2.0                      ║
║              Comprehensive DNS Security Testing                ║
║                                                               ║
║  Author: rfs85                                                ║
║  GitHub: https://github.com/rfs85/RFS-DNS-Framework           ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, style="bold blue"))

    def list_tools(self):
        """Display available tools"""
        table = Table(title="Available Tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Status", style="yellow")
        
        for tool_name, tool_info in self.tools.items():
            status = "[green]Available" if tool_info['module'] else "[red]Not Found"
            table.add_row(tool_name, tool_info['description'], status)
        
        self.console.print(table)

    def run_tool(self, tool_name: str, args: list):
        """Run a specific tool with arguments"""
        if tool_name not in self.tools:
            self.console.print(f"[red]Error: Tool '{tool_name}' not found")
            return False
        
        tool_info = self.tools[tool_name]
        if not tool_info['module']:
            self.console.print(f"[red]Error: Tool '{tool_name}' could not be loaded")
            return False
        
        try:
            # Create a new argv for the tool
            tool_argv = [tool_info['script']] + args
            sys.argv = tool_argv
            
            # Run the tool's main function
            if hasattr(tool_info['module'], 'main'):
                result = tool_info['module'].main()
                
                # Handle framework-mode JSON output
                if tool_name == 'takeover' and '--framework-mode' in args:
                    try:
                        # Parse the JSON output
                        if isinstance(result, str):
                            result_data = json.loads(result)
                        elif isinstance(result, dict):
                            result_data = result
                        else:
                            return True  # Default to success if output format unknown
                        
                        # Check status
                        if result_data.get('status') == 'error':
                            self.console.print(f"[red]Error in {tool_name}: {result_data.get('error', 'Unknown error')}")
                            return False
                        
                        # Display findings summary
                        vulnerabilities = result_data.get('vulnerabilities', 0)
                        risk_summary = result_data.get('risk_summary', {})
                        
                        if vulnerabilities > 0:
                            self.console.print(f"[yellow]Found {vulnerabilities} potential takeover vulnerabilities:")
                            self.console.print(f"[red]  High Risk: {risk_summary.get('High', 0)}")
                            self.console.print(f"[yellow]  Medium Risk: {risk_summary.get('Medium', 0)}")
                            self.console.print(f"[blue]  Low Risk: {risk_summary.get('Low', 0)}")
                        
                        return True
                    except json.JSONDecodeError:
                        return True  # Continue if output is not JSON
                
                return True
            else:
                self.console.print(f"[red]Error: Tool '{tool_name}' has no main function")
                return False
            
        except Exception as e:
            self.console.print(f"[red]Error running {tool_name}: {e}")
            return False

    def detect_nameservers(self, domain: str) -> list:
        """Detect nameservers for a domain"""
        if domain in self.cached_nameservers:
            return self.cached_nameservers[domain]

        try:
            import dns.resolver
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

    def run_workflow(self, domain: str, output_dir: str):
        """Run a complete DNS analysis workflow"""
        self.console.print(f"[blue]Starting comprehensive DNS analysis for {domain}")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Store results for each step
        workflow_results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'steps': {},
            'nameservers': []
        }
        
        # Detect nameservers first
        nameservers = self.detect_nameservers(domain)
        workflow_results['nameservers'] = nameservers
        self.console.print(f"[blue]Detected nameservers: {', '.join(nameservers)}")
        
        # Define tool execution order
        tool_order = [
            'dns-enum',      # Start with DNS enumeration
            'find-server',   # Find DNS servers
            'tld-brute',    # Discover TLDs
            'cloud-enum',    # Analyze cloud providers
            'takeover',      # Check for takeovers
            'cache-poison'   # Test for cache poisoning
        ]
        
        with Progress() as progress:
            total_steps = len(tool_order)
            task = progress.add_task("[cyan]Running workflow...", total=total_steps)
            
            for step, tool_name in enumerate(tool_order, 1):
                tool_info = self.tools[tool_name]
                step_output = os.path.join(output_dir, f"{tool_name}_results.json")
                
                self.console.print(f"\n[yellow]Step {step}/{total_steps}: Running {tool_info['description']}")
                
                try:
                    # Create results directory for this step
                    step_dir = os.path.join(output_dir, tool_name)
                    os.makedirs(step_dir, exist_ok=True)
                    
                    # Get tool-specific arguments
                    if tool_info.get('requires_nameserver'):
                        # Use first detected nameserver for tools that require it
                        args = tool_info['workflow_args'](domain, step_output, nameservers[0])
                    else:
                        args = tool_info['workflow_args'](domain, step_output)
                    
                    # Run the tool
                    success = self.run_tool(tool_name, args)
                    
                    # Store results
                    workflow_results['steps'][tool_name] = {
                        'success': success,
                        'output_file': step_output if success else None,
                        'output_dir': step_dir,
                        'timestamp': datetime.now().isoformat(),
                        'args_used': args
                    }
                    
                    if not success:
                        self.console.print(f"[red]Warning: {tool_name} failed or had errors")
                    
                except Exception as e:
                    self.console.print(f"[red]Error in {tool_name}: {e}")
                    workflow_results['steps'][tool_name] = {
                        'success': False,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                
                progress.update(task, advance=1)
                
                # Add delay between tools to prevent rate limiting
                time.sleep(1)
        
        # Save workflow summary
        summary_file = os.path.join(output_dir, "workflow_summary.json")
        try:
            with open(summary_file, 'w') as f:
                json.dump(workflow_results, f, indent=4)
            self.console.print(f"\n[green]Workflow summary saved to {summary_file}")
        except Exception as e:
            self.console.print(f"[red]Error saving workflow summary: {e}")
        
        # Display final summary
        self.display_workflow_summary(workflow_results)

    def display_workflow_summary(self, results):
        """Display a summary of the workflow results"""
        # Display detected nameservers
        if results.get('nameservers'):
            self.console.print("\n[blue]Detected Nameservers:")
            for ns in results['nameservers']:
                self.console.print(f"[blue]  - {ns}")

        # Display tool execution summary
        table = Table(title=f"Workflow Summary for {results['domain']}")
        table.add_column("Tool", style="cyan", width=20)
        table.add_column("Status", style="green", width=10)
        table.add_column("Duration", style="yellow", width=10)
        table.add_column("Output", style="blue")
        
        for tool_name, step_result in results['steps'].items():
            # Calculate duration if timestamps available
            duration = "N/A"
            if 'timestamp' in step_result and results['timestamp']:
                try:
                    start = datetime.fromisoformat(results['timestamp'])
                    end = datetime.fromisoformat(step_result['timestamp'])
                    duration = str(end - start)
                except:
                    pass
            
            status = "[green]Success" if step_result.get('success') else "[red]Failed"
            output = step_result.get('output_file', 'N/A')
            if 'error' in step_result:
                output = f"Error: {step_result['error']}"
            
            table.add_row(tool_name, status, duration, output)
        
        self.console.print("\n", table)

def main():
    parser = argparse.ArgumentParser(
        description="RFS DNS Framework - Comprehensive DNS Security Testing"
    )
    parser.add_argument('--list-tools', action='store_true',
                      help='List available tools')
    parser.add_argument('--tool', choices=[
        'dns-enum', 'find-server', 'cloud-enum',
        'tld-brute', 'takeover', 'cache-poison'
    ], help='Run a specific tool')
    parser.add_argument('--workflow', action='store_true',
                      help='Run complete DNS analysis workflow')
    parser.add_argument('--domain',
                      help='Target domain for analysis')
    parser.add_argument('--output-dir', default='results',
                      help='Output directory for results')
    parser.add_argument('tool_args', nargs=argparse.REMAINDER,
                      help='Arguments to pass to the tool')
    
    args = parser.parse_args()
    
    # Initialize framework
    framework = RFSDNSFramework()
    framework.display_banner()
    
    if args.list_tools:
        framework.list_tools()
    elif args.workflow:
        if not args.domain:
            framework.console.print("[red]Error: --domain is required for workflow")
            sys.exit(1)
        framework.run_workflow(args.domain, args.output_dir)
    elif args.tool:
        success = framework.run_tool(args.tool, args.tool_args)
        if not success:
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1) 