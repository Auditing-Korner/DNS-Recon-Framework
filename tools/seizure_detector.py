#!/usr/bin/env python3
"""
Domain Seizure Detector

Detects law enforcement domain seizures:
- DNS record analysis
- WHOIS changes detection
- HTTP evidence collection
- Multi-threaded scanning
"""

import argparse
import json
import logging
import sys
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from rich.logging import RichHandler
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

try:
    from .base_tool import BaseTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.base_tool import BaseTool, ToolResult

# Initialize rich console
console = Console()

def print_banner():
    """Print a visually appealing banner"""
    title = Text()
    title.append("Domain Seizure Detector", style="bold red")
    title.append("\nLaw Enforcement Domain Seizure Analysis", style="bright_red")
    
    version = Text("\nVersion: 1.0.0", style="yellow")
    author = Text("\nAuthor: rfs85", style="green")
    
    features = Text("\n\nFeatures:", style="bold magenta")
    features.append("\n• Detects law enforcement domain seizures", style="magenta")
    features.append("\n• Analyzes DNS, WHOIS, and HTTP evidence", style="magenta")
    features.append("\n• Multi-threaded scanning capabilities", style="magenta")
    features.append("\n• Detailed seizure reporting", style="magenta")
    
    agencies = Text("\n\nSupported Agencies:", style="bold yellow")
    agencies.append("\n• FBI & US Law Enforcement", style="yellow")
    agencies.append("\n• Europol & International Agencies", style="yellow")
    agencies.append("\n• ICE/HSI & Customs Enforcement", style="yellow")
    agencies.append("\n• Department of Justice", style="yellow")
    agencies.append("\n• And more...", style="yellow")
    
    banner = title + version + author + features + agencies
    
    console.print(Panel(
        banner,
        title="[bold white]RFS DNS Framework[/bold white]",
        subtitle="[bold white]Security Testing Tool[/bold white]",
        border_style="red",
        box=box.DOUBLE,
        padding=(1, 2),
        expand=False
    ))
    console.print()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Check for required dependencies
MISSING_DEPS = []
try:
    import requests
except ImportError:
    MISSING_DEPS.append("requests")

try:
    import dns.resolver
except ImportError:
    MISSING_DEPS.append("dnspython")

try:
    import whois
except ImportError:
    MISSING_DEPS.append("python-whois")

try:
    from urllib3.exceptions import InsecureRequestWarning
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
except ImportError:
    MISSING_DEPS.append("urllib3")

def check_dependencies():
    """Check if all required dependencies are installed"""
    if MISSING_DEPS:
        print("Error: Missing required dependencies:")
        for dep in MISSING_DEPS:
            print(f"  - {dep}")
        print("\nPlease install the missing dependencies using:")
        print("pip install -r requirements.txt")
        return False, f"Missing required dependencies: {', '.join(MISSING_DEPS)}"
    return True, None

@dataclass
class SeizureResult:
    domain: str
    is_seized: bool
    agency: Optional[str]
    evidence: List[str]
    risk_level: str
    timestamp: str
    whois_changes: Dict
    dns_changes: Dict
    http_evidence: Dict

class SeizureDetector(BaseTool):
    """Law Enforcement Domain Seizure Detection Tool"""
    
    def __init__(self):
        super().__init__(
            name="seizure-detector",
            description="Law Enforcement Domain Seizure Detection Tool"
        )
        self.results = []
        
        # Load signature database
        self.signatures = self._load_signatures()
        
        # Common User-Agent for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing"""
        parser.add_argument('domain', help='Domain to analyze')
        parser.add_argument('--threads', type=int, default=10,
                          help='Number of concurrent threads')
        parser.add_argument('--check-whois', action='store_true',
                          help='Check WHOIS record changes')
        parser.add_argument('--check-dns', action='store_true',
                          help='Check DNS record changes')
        parser.add_argument('--check-http', action='store_true',
                          help='Check HTTP evidence')
        parser.add_argument('--check-all', action='store_true',
                          help='Run all checks')
        parser.add_argument('--html-report', action='store_true',
                          help='Generate HTML report')
        
        # Framework integration arguments
        parser.add_argument('--output', help='Output file path for results')
        parser.add_argument('--framework-mode', action='store_true',
                          help='Run in framework integration mode')
    
    def run(self, args: argparse.Namespace) -> ToolResult:
        """Execute seizure detection analysis"""
        result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={
                "domain": args.domain,
                "timestamp": datetime.now().isoformat(),
                "framework_mode": args.framework_mode if hasattr(args, 'framework_mode') else False,
                "checks": {
                    "whois": args.check_all or args.check_whois,
                    "dns": args.check_all or args.check_dns,
                    "http": args.check_all or args.check_http
                }
            }
        )
        
        try:
            # Check dependencies
            deps_ok, error_msg = check_dependencies()
            if not deps_ok:
                result.add_error(error_msg)
                return result
            
            # Only show banner in non-framework mode
            if not hasattr(args, 'framework_mode') or not args.framework_mode:
                print_banner()
            
            # Analyze domain
            seizure_result = self.analyze_domain(args.domain, args)
            
            # Add findings based on analysis
            if seizure_result.is_seized:
                result.add_finding(
                    title=f"Domain Seizure Detected: {seizure_result.domain}",
                    description=f"Domain appears to be seized by {seizure_result.agency}" if seizure_result.agency else "Domain appears to be seized by law enforcement",
                    risk_level="Critical",
                    evidence="\n".join(seizure_result.evidence)
                )
            
            # Add WHOIS findings
            if seizure_result.whois_changes:
                for change in seizure_result.whois_changes.get("changes", []):
                    result.add_finding(
                        title="WHOIS Record Change Detected",
                        description=change["description"],
                        risk_level=change["risk_level"],
                        evidence=json.dumps(change["details"], indent=2)
                    )
            
            # Add DNS findings
            if seizure_result.dns_changes:
                for change in seizure_result.dns_changes.get("changes", []):
                    result.add_finding(
                        title="DNS Record Change Detected",
                        description=change["description"],
                        risk_level=change["risk_level"],
                        evidence=json.dumps(change["details"], indent=2)
                    )
            
            # Add HTTP evidence
            if seizure_result.http_evidence:
                for evidence in seizure_result.http_evidence.get("evidence", []):
                    result.add_finding(
                        title="HTTP Evidence Found",
                        description=evidence["description"],
                        risk_level=evidence["risk_level"],
                        evidence=json.dumps(evidence["details"], indent=2)
                    )
            
            # Add risk summary for framework integration
            if hasattr(args, 'framework_mode') and args.framework_mode:
                risk_summary = {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                }
                for finding in result.findings:
                    risk_summary[finding.get('risk_level', 'Info')] += 1
                result.metadata['risk_summary'] = risk_summary
            
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
            
            # Generate HTML report if requested
            if args.html_report:
                try:
                    html_report = self.generate_html_report([seizure_result])
                    report_path = args.output.replace('.json', '.html') if args.output else 'seizure_report.html'
                    with open(report_path, 'w') as f:
                        f.write(html_report)
                    result.metadata['html_report'] = report_path
                except Exception as e:
                    result.add_error(f"Error generating HTML report: {str(e)}")
            
            return result
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during analysis: {str(e)}")
            return result

    def analyze_domain(self, domain: str, args: argparse.Namespace) -> SeizureResult:
        """Analyze a domain for seizure indicators"""
        evidence = []
        whois_changes = {}
        dns_changes = {}
        http_evidence = {}
        
        # Run enabled checks
        if args.check_all or args.check_whois:
            whois_changes = self.check_whois_changes(domain)
            if whois_changes.get("changes"):
                evidence.extend([c["description"] for c in whois_changes["changes"]])
        
        if args.check_all or args.check_dns:
            dns_changes = self.check_dns_records(domain)
            if dns_changes.get("changes"):
                evidence.extend([c["description"] for c in dns_changes["changes"]])
        
        if args.check_all or args.check_http:
            http_evidence = self.check_http_evidence(domain)
            if http_evidence.get("evidence"):
                evidence.extend([e["description"] for e in http_evidence["evidence"]])
        
        # Determine if domain is seized
        is_seized = bool(evidence)
        agency = self._determine_agency(evidence) if is_seized else None
        risk_level = "Critical" if is_seized else "Info"
        
        return SeizureResult(
            domain=domain,
            is_seized=is_seized,
            agency=agency,
            evidence=evidence,
            risk_level=risk_level,
            timestamp=datetime.now().isoformat(),
            whois_changes=whois_changes,
            dns_changes=dns_changes,
            http_evidence=http_evidence
        )

    def check_whois_changes(self, domain: str) -> Dict:
        """Check for suspicious WHOIS record changes"""
        changes = []
        try:
            w = whois.whois(domain)
            
            # Check registrar changes
            if w.registrar and any(sig in str(w.registrar).lower() for sig in self.signatures["registrars"]):
                changes.append({
                    "description": "Domain registrar changed to known law enforcement registrar",
                    "risk_level": "High",
                    "details": {"registrar": w.registrar}
                })
            
            # Check nameserver changes
            if w.name_servers:
                for ns in w.name_servers:
                    if any(sig in str(ns).lower() for sig in self.signatures["nameservers"]):
                        changes.append({
                            "description": "Domain nameservers changed to known law enforcement servers",
                            "risk_level": "High",
                            "details": {"nameserver": ns}
                        })
            
            return {"changes": changes}
            
        except Exception as e:
            return {"error": str(e)}

    def check_dns_records(self, domain: str) -> Dict:
        """Check for suspicious DNS record changes"""
        changes = []
        try:
            resolver = dns.resolver.Resolver()
            
            # Check A records
            try:
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if any(sig in ip for sig in self.signatures["ip_addresses"]):
                        changes.append({
                            "description": "Domain points to known law enforcement IP address",
                            "risk_level": "High",
                            "details": {"ip": ip}
                        })
            except:
                pass
            
            # Check TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = str(rdata)
                    if any(sig in txt.lower() for sig in self.signatures["txt_records"]):
                        changes.append({
                            "description": "Domain contains law enforcement TXT record",
                            "risk_level": "High",
                            "details": {"txt": txt}
                        })
            except:
                pass
            
            return {"changes": changes}
            
        except Exception as e:
            return {"error": str(e)}

    def check_http_evidence(self, domain: str) -> Dict:
        """Check for seizure notice on website"""
        evidence = []
        try:
            urls = [
                f"http://{domain}",
                f"https://{domain}",
                f"http://www.{domain}",
                f"https://www.{domain}"
            ]
            
            for url in urls:
                try:
                    response = requests.get(url, headers=self.headers, verify=False, timeout=10)
                    
                    # Check response code
                    if response.status_code == 200:
                        # Check page content
                        content = response.text.lower()
                        for pattern in self.signatures["page_content"]:
                            if pattern in content:
                                evidence.append({
                                    "description": "Domain displays law enforcement seizure notice",
                                    "risk_level": "Critical",
                                    "details": {
                                        "url": url,
                                        "pattern": pattern
                                    }
                                })
                        
                        # Check for agency logos
                        for logo in self.signatures["logos"]:
                            if logo in content:
                                evidence.append({
                                    "description": "Domain displays law enforcement agency logo",
                                    "risk_level": "High",
                                    "details": {
                                        "url": url,
                                        "logo": logo
                                    }
                                })
                except:
                    continue
            
            return {"evidence": evidence}
            
        except Exception as e:
            return {"error": str(e)}

    def _load_signatures(self) -> Dict:
        """Load seizure signatures from configuration"""
        try:
            signature_file = Path(__file__).parent / "data" / "seizure_signatures.json"
            if signature_file.exists():
                with open(signature_file) as f:
                    return json.load(f)
        except:
            pass
        
        # Default signatures if file not found
        return {
            "registrars": [
                "us department of justice",
                "europol",
                "interpol",
                "federal bureau of investigation"
            ],
            "nameservers": [
                "ns.fbi.gov",
                "ns.europol.europa.eu",
                "ns.justice.gov"
            ],
            "ip_addresses": [
                "153.31.",
                "194.185.142."
            ],
            "txt_records": [
                "seized by fbi",
                "seized by europol",
                "law enforcement action"
            ],
            "page_content": [
                "this domain has been seized",
                "law enforcement action",
                "federal bureau of investigation",
                "europol operation"
            ],
            "logos": [
                "fbi-logo.png",
                "europol-logo.png",
                "doj-logo.png"
            ]
        }

    def _determine_agency(self, evidence: List[str]) -> Optional[str]:
        """Determine seizing agency from evidence"""
        evidence_str = " ".join(evidence).lower()
        
        if "fbi" in evidence_str or "federal bureau" in evidence_str:
            return "FBI"
        elif "europol" in evidence_str:
            return "Europol"
        elif "ice" in evidence_str or "homeland" in evidence_str:
            return "ICE/HSI"
        elif "justice" in evidence_str or "doj" in evidence_str:
            return "Department of Justice"
        
        return None

    def generate_html_report(self, results: List[SeizureResult]) -> str:
        """Generate HTML report from results"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Domain Seizure Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { text-align: center; margin-bottom: 30px; }
                .result { border: 1px solid #ddd; padding: 20px; margin: 20px 0; }
                .seized { border-left: 5px solid #ff0000; }
                .evidence { background: #f5f5f5; padding: 10px; margin: 10px 0; }
                .changes { margin: 10px 0; }
                .timestamp { color: #666; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Domain Seizure Analysis Report</h1>
                <p>Generated: {timestamp}</p>
            </div>
            
            {results_html}
        </body>
        </html>
        """
        
        results_html = []
        for r in results:
            seized_class = "seized" if r.is_seized else ""
            evidence_html = "\n".join(f"<div class='evidence'>{e}</div>" for e in r.evidence)
            
            result_html = f"""
            <div class="result {seized_class}">
                <h2>Domain: {r.domain}</h2>
                <p>Status: {"SEIZED" if r.is_seized else "Not Seized"}</p>
                {f"<p>Seizing Agency: {r.agency}</p>" if r.agency else ""}
                <p>Risk Level: {r.risk_level}</p>
                
                <h3>Evidence:</h3>
                {evidence_html}
                
                <div class="changes">
                    <h3>WHOIS Changes:</h3>
                    <pre>{json.dumps(r.whois_changes, indent=2)}</pre>
                    
                    <h3>DNS Changes:</h3>
                    <pre>{json.dumps(r.dns_changes, indent=2)}</pre>
                    
                    <h3>HTTP Evidence:</h3>
                    <pre>{json.dumps(r.http_evidence, indent=2)}</pre>
                </div>
                
                <div class="timestamp">
                    Analysis Time: {r.timestamp}
                </div>
            </div>
            """
            results_html.append(result_html)
        
        return template.format(
            timestamp=datetime.now().isoformat(),
            results_html="\n".join(results_html)
        )

def main():
    """Main function for standalone usage"""
    tool = SeizureDetector()
    parser = argparse.ArgumentParser(description=tool.description)
    tool.setup_argparse(parser)
    args = parser.parse_args()
    
    result = tool.run(args)
    
    if args.output:
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(result.to_dict(), indent=2))
    
    sys.exit(0 if result.success else 1)

if __name__ == "__main__":
    main() 