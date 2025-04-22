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
    from .framework_tool_template import FrameworkTool, ToolResult
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.framework_tool_template import FrameworkTool, ToolResult

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

class SeizureDetector(FrameworkTool):
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
    
    def setup_tool_arguments(self, parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup]) -> None:
        """Set up tool-specific arguments"""
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
    
    def execute_tool(self, args: argparse.Namespace, result: ToolResult) -> None:
        """Execute seizure detection analysis"""
        try:
            # Check dependencies
            deps_ok, error_msg = check_dependencies()
            if not deps_ok:
                result.add_error(error_msg)
                return
            
            # Update metadata
            result.metadata.update({
                "domain": args.domain,
                "timestamp": datetime.now().isoformat(),
                "checks": {
                    "whois": args.check_all or args.check_whois,
                    "dns": args.check_all or args.check_dns,
                    "http": args.check_all or args.check_http
                }
            })
            
            # Only show banner in non-framework mode
            if not self.is_framework_mode():
                print_banner()
            
            # Analyze domain
            seizure_result = self.analyze_domain(args.domain, args)
            
            # Add findings based on analysis
            if seizure_result.is_seized:
                self.add_common_finding(
                    result,
                    title=f"Domain Seizure Detected: {seizure_result.domain}",
                    description=f"Domain appears to be seized by {seizure_result.agency}" if seizure_result.agency else "Domain appears to be seized by law enforcement",
                    risk_level="Critical",
                    evidence="\n".join(seizure_result.evidence)
                )
            
            # Add WHOIS findings
            if seizure_result.whois_changes:
                for change in seizure_result.whois_changes.get("changes", []):
                    self.add_common_finding(
                        result,
                        title=f"WHOIS Change Detected: {change.get('field', 'Unknown')}",
                        description=f"WHOIS record change detected for {seizure_result.domain}",
                        risk_level="Medium",
                        evidence=f"Old: {change.get('old', 'N/A')}\nNew: {change.get('new', 'N/A')}"
                    )
            
            # Add DNS findings
            if seizure_result.dns_changes:
                for record_type, changes in seizure_result.dns_changes.items():
                    if changes.get("suspicious", False):
                        self.add_common_finding(
                            result,
                            title=f"Suspicious DNS Change: {record_type}",
                            description=f"Suspicious DNS record change detected for {seizure_result.domain}",
                            risk_level="High",
                            evidence=f"Current Records: {changes.get('current', [])}\nKnown Seizure IPs: {changes.get('seizure_ips', [])}"
                        )
            
            # Add HTTP findings
            if seizure_result.http_evidence:
                if seizure_result.http_evidence.get("seizure_page", False):
                    self.add_common_finding(
                        result,
                        title="Seizure Notice Page Detected",
                        description=f"Law enforcement seizure notice page detected for {seizure_result.domain}",
                        risk_level="Critical",
                        evidence=seizure_result.http_evidence.get("evidence", "No specific evidence")
                    )
            
            # Generate HTML report if requested
            if args.html_report and self.get_output_file():
                html_report = self.generate_html_report([seizure_result])
                report_path = Path(self.get_output_file()).parent / f"{seizure_result.domain}_seizure_report.html"
                try:
                    with open(report_path, 'w', encoding='utf-8') as f:
                        f.write(html_report)
                    result.metadata["html_report"] = str(report_path)
                except Exception as e:
                    result.add_error(f"Error writing HTML report: {str(e)}")
            
            # Set success status
            result.success = True
            
        except Exception as e:
            result.success = False
            result.add_error(f"Error during seizure detection: {str(e)}")
            if not self.is_framework_mode():
                logger.error(f"Error: {str(e)}")
    
    def analyze_domain(self, domain: str, args: argparse.Namespace) -> SeizureResult:
        """Analyze a domain for seizure evidence"""
        whois_changes = {}
        dns_changes = {}
        http_evidence = {}
        evidence = []
        
        try:
            # Run selected checks
            if args.check_all or args.check_whois:
                whois_changes = self.check_whois_changes(domain)
                if whois_changes.get("evidence"):
                    evidence.extend(whois_changes["evidence"])
            
            if args.check_all or args.check_dns:
                dns_changes = self.check_dns_records(domain)
                if dns_changes.get("evidence"):
                    evidence.extend(dns_changes["evidence"])
            
            if args.check_all or args.check_http:
                http_evidence = self.check_http_evidence(domain)
                if http_evidence.get("evidence"):
                    evidence.extend(http_evidence["evidence"])
            
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
            
        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {str(e)}")
            return SeizureResult(
                domain=domain,
                is_seized=False,
                agency=None,
                evidence=[f"Error during analysis: {str(e)}"],
                risk_level="Error",
                timestamp=datetime.now().isoformat(),
                whois_changes={},
                dns_changes={},
                http_evidence={}
            )
    
    def check_whois_changes(self, domain: str) -> Dict:
        """Check for suspicious WHOIS record changes"""
        try:
            w = whois.whois(domain)
            changes = []
            evidence = []
            
            # Check for law enforcement registrars
            if w.registrar and any(org.lower() in w.registrar.lower() 
                                 for org in self.signatures.get("registrars", [])):
                changes.append({
                    "field": "registrar",
                    "old": "Unknown",
                    "new": w.registrar,
                    "date": str(w.updated_date)
                })
                evidence.append(f"Domain registered with known law enforcement registrar: {w.registrar}")
            
            return {"changes": changes, "evidence": evidence}
            
        except Exception as e:
            return {"error": str(e)}
    
    def check_dns_records(self, domain: str) -> Dict:
        """Check for suspicious DNS record changes"""
        try:
            resolver = dns.resolver.Resolver()
            changes = []
            evidence = []
            
            # Check A records
            try:
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if any(ip.startswith(prefix) for prefix in self.signatures.get("ip_ranges", [])):
                        changes.append({
                            "type": "A",
                            "description": f"IP address {ip} matches known law enforcement range",
                            "evidence": f"IP: {ip}"
                        })
                        evidence.append(f"Domain resolves to known law enforcement IP: {ip}")
            except:
                pass
            
            return {"changes": changes, "evidence": evidence}
            
        except Exception as e:
            return {"error": str(e)}
    
    def check_http_evidence(self, domain: str) -> Dict:
        """Check for seizure notice on website"""
        try:
            evidence = []
            
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{domain}"
                    response = requests.get(url, headers=self.headers, verify=False, timeout=10)
                    
                    # Check for seizure notice keywords
                    content = response.text.lower()
                    for keyword in self.signatures.get("keywords", []):
                        if keyword.lower() in content:
                            evidence.append({
                                "description": f"Found seizure keyword: {keyword}",
                                "risk_level": "High",
                                "details": f"Found in {url}"
                            })
                    
                    # Check for seizure notice images
                    for image in self.signatures.get("images", []):
                        if image.lower() in content:
                            evidence.append({
                                "description": f"Found seizure notice image: {image}",
                                "risk_level": "Critical",
                                "details": f"Found in {url}"
                            })
                    
                    break  # Stop if successful
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
                "US Department of Justice",
                "Europol",
                "FBI",
                "ICE"
            ],
            "ip_ranges": [
                "159.46.",
                "192.168.1."  # Example range
            ],
            "keywords": [
                "seized",
                "forfeited",
                "law enforcement",
                "federal bureau of investigation",
                "europol"
            ],
            "images": [
                "seized_banner.jpg",
                "doj_seal.png",
                "fbi_seal.png"
            ]
        }
    
    def _determine_agency(self, evidence: List[str]) -> Optional[str]:
        """Determine which agency seized the domain based on evidence"""
        evidence_text = " ".join(evidence).lower()
        
        if "fbi" in evidence_text or "federal bureau" in evidence_text:
            return "FBI"
        elif "ice" in evidence_text or "homeland" in evidence_text:
            return "ICE/HSI"
        elif "europol" in evidence_text:
            return "Europol"
        elif "justice" in evidence_text or "doj" in evidence_text:
            return "Department of Justice"
        
        return None
    
    def generate_html_report(self, results: List[SeizureResult]) -> str:
        """Generate an HTML report of seizure analysis results"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Domain Seizure Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .seized { color: red; }
                .clean { color: green; }
                .evidence { margin-left: 20px; }
            </style>
        </head>
        <body>
            <h1>Domain Seizure Analysis Report</h1>
            <p>Generated: {date}</p>
        """.format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        for result in results:
            status_class = "seized" if result.is_seized else "clean"
            status_text = "SEIZED" if result.is_seized else "CLEAN"
            
            html += f"""
            <div class="domain">
                <h2>Domain: {result.domain}</h2>
                <p>Status: <span class="{status_class}">{status_text}</span></p>
            """
            
            if result.is_seized:
                html += f"""
                <p>Seizing Agency: {result.agency or 'Unknown'}</p>
                <h3>Evidence:</h3>
                <ul class="evidence">
                """
                for item in result.evidence:
                    html += f"<li>{item}</li>"
                html += "</ul>"
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html

def main():
    """Main entry point for the tool"""
    tool = SeizureDetector()
    parser = argparse.ArgumentParser(description=tool.description)
    tool.setup_argparse(parser)
    args = parser.parse_args()
    result = tool.run(args)
    sys.exit(0 if result.success else 1)

if __name__ == "__main__":
    main() 