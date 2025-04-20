#!/usr/bin/env python3

import argparse
import json
import logging
import sys
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
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
    def __init__(self):
        super().__init__(
            name="seizure_detector",
            description="Law Enforcement Domain Seizure Detector"
        )
        self.results = []
        
        # Load signature database
        self.signatures = self._load_signatures()
        
        # Common User-Agent for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def setup_argparse(self, parser: argparse.ArgumentParser) -> None:
        """Set up argument parsing for the tool"""
        super().setup_argparse(parser)
        parser.add_argument("domains", nargs="+", help="Domain(s) to check")
        parser.add_argument("--threads", "-t", type=int, default=10,
                          help="Number of concurrent threads")
        parser.add_argument("--html", action="store_true",
                          help="Generate HTML report")

    def check_dependencies(self) -> Tuple[bool, Optional[str]]:
        """Check if all required dependencies are available"""
        if MISSING_DEPS:
            return False, f"Missing required dependencies: {', '.join(MISSING_DEPS)}"
        return True, None

    def run(self, args: argparse.Namespace) -> ToolResult:
        """Run the seizure detection analysis"""
        tool_result = ToolResult(
            success=True,
            tool_name=self.name,
            findings=[],
            metadata={"domains_analyzed": args.domains}
        )

        # Set framework mode flag if specified
        self.framework_mode = args.framework_mode if hasattr(args, 'framework_mode') else False

        try:
            if len(args.domains) == 1:
                result = self.analyze_domain(args.domains[0])
                self._add_result_to_tool_result(result, tool_result)
            else:
                results = self.scan_domains(args.domains, args.threads)
                for result in results:
                    self._add_result_to_tool_result(result, tool_result)

            return tool_result

        except Exception as e:
            tool_result.success = False
            tool_result.add_error(f"Error during seizure detection: {str(e)}")
            return tool_result

    def _add_result_to_tool_result(self, seizure_result: SeizureResult, tool_result: ToolResult):
        """Add a SeizureResult to the ToolResult"""
        if seizure_result.is_seized:
            title = f"Domain Seizure Detected: {seizure_result.domain}"
            description = f"Domain appears to be seized by {seizure_result.agency}" if seizure_result.agency else "Domain appears to be seized by law enforcement"
            evidence = "\n".join(seizure_result.evidence)
            tool_result.add_finding(title, description, seizure_result.risk_level, evidence)
        
        # Add any errors or warnings from the analysis
        if seizure_result.http_evidence.get("errors"):
            for error in seizure_result.http_evidence["errors"]:
                tool_result.add_warning(f"HTTP analysis error for {seizure_result.domain}: {error}")
        
        if seizure_result.dns_changes.get("errors"):
            for error in seizure_result.dns_changes["errors"]:
                tool_result.add_warning(f"DNS analysis error for {seizure_result.domain}: {error}")

    def _handle_error(self, error_type: str, domain: str, error: Exception) -> Dict:
        """Unified error handling"""
        error_msg = f"Error during {error_type} check for {domain}: {str(error)}"
        self.log_message('warning', error_msg)
        self.errors.append({
            "type": error_type,
            "domain": domain,
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        })
        return {"error": str(error), "error_type": error_type}

    def _load_signatures(self) -> Dict:
        """Load seizure signatures from the signatures database"""
        signatures_file = Path(__file__).parent / "data" / "seizure_signatures.json"
        try:
            with open(signatures_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load signatures: {e}")
            return {}

    def log_message(self, level: str, message: str):
        """Unified logging that respects framework mode"""
        if self.framework_mode:
            # In framework mode, collect messages
            if not hasattr(self, 'messages'):
                self.messages = []
            self.messages.append({"level": level, "message": message})
        else:
            # In standalone mode, use logger
            if level == 'info':
                logger.info(message)
            elif level == 'warning':
                logger.warning(message)
            elif level == 'error':
                logger.error(message)

    def check_whois_changes(self, domain: str) -> Dict:
        """Check for suspicious WHOIS changes"""
        try:
            w = whois.whois(domain)
            changes = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "updated_date": w.updated_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "status": w.status,
                "errors": []
            }
            return changes
        except Exception as e:
            return self._handle_error("WHOIS", domain, e)

    def check_dns_records(self, domain: str) -> Dict:
        """Check for DNS record changes indicating seizure"""
        changes = {"records": {}, "errors": []}
        
        for record_type in ["A", "AAAA", "NS", "MX", "TXT"]:
            try:
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(domain, record_type)
                changes["records"][record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                changes["errors"].append(f"{record_type} lookup failed: {str(e)}")
        
        return changes

    def check_http_evidence(self, domain: str) -> Dict:
        """Check for HTTP evidence of seizure"""
        evidence = {
            "title": None,
            "content": None,
            "status_code": None,
            "server": None,
            "redirect_url": None,
            "errors": []
        }

        urls = [f"http://{domain}", f"https://{domain}"]
        
        for url in urls:
            try:
                response = requests.get(url, headers=self.headers, verify=False, timeout=10)
                evidence["status_code"] = response.status_code
                evidence["server"] = response.headers.get("Server")
                
                if response.history:
                    evidence["redirect_url"] = response.url
                
                # Extract title and check content
                content = response.text.lower()
                title_match = re.search(r"<title>(.*?)</title>", content)
                if title_match:
                    evidence["title"] = title_match.group(1)
                evidence["content"] = content
                
                break  # Stop if we get a successful response
            except Exception as e:
                evidence["errors"].append(f"HTTP request failed for {url}: {str(e)}")
        
        return evidence

    def analyze_domain(self, domain: str) -> SeizureResult:
        """Analyze a single domain for signs of seizure"""
        whois_changes = self.check_whois_changes(domain)
        dns_changes = self.check_dns_records(domain)
        http_evidence = self.check_http_evidence(domain)
        
        is_seized = False
        agency = None
        evidence = []
        risk_level = "info"
        
        # Check for seizure evidence
        if http_evidence.get("content"):
            content = http_evidence["content"]
            title = http_evidence.get("title", "").lower()
            
            for sig in self.signatures.get("content_signatures", []):
                if sig["pattern"].lower() in content:
                    is_seized = True
                    agency = sig.get("agency")
                    evidence.append(f"Content match: {sig['pattern']}")
                    risk_level = sig.get("risk_level", "high")
            
            for sig in self.signatures.get("title_signatures", []):
                if sig["pattern"].lower() in title:
                    is_seized = True
                    agency = sig.get("agency")
                    evidence.append(f"Title match: {sig['pattern']}")
                    risk_level = sig.get("risk_level", "high")
        
        # Check DNS patterns
        for record_type, records in dns_changes.get("records", {}).items():
            for record in records:
                for sig in self.signatures.get("dns_signatures", []):
                    if sig["pattern"].lower() in record.lower():
                        is_seized = True
                        agency = sig.get("agency")
                        evidence.append(f"DNS {record_type} match: {sig['pattern']}")
                        risk_level = sig.get("risk_level", "high")
        
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

    def scan_domains(self, domains: List[str], threads: int = 10) -> List[SeizureResult]:
        """Scan multiple domains concurrently"""
        with ThreadPoolExecutor(max_workers=threads) as executor:
            return list(executor.map(self.analyze_domain, domains))

    def generate_html_report(self, results: List[SeizureResult]) -> str:
        """Generate an HTML report from the results"""
        html = """
        <html>
        <head>
            <title>Domain Seizure Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .domain { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }
                .seized { background-color: #ffebee; }
                .evidence { margin-left: 20px; }
                .error { color: red; }
                .warning { color: orange; }
            </style>
        </head>
        <body>
            <h1>Domain Seizure Analysis Report</h1>
            <p>Generated: {timestamp}</p>
        """.format(timestamp=datetime.now().isoformat())

        for result in results:
            html += """
            <div class="domain{seized}">
                <h2>{domain}</h2>
                <p>Status: {status}</p>
                {agency}
                {evidence}
                <h3>WHOIS Changes</h3>
                <pre>{whois}</pre>
                <h3>DNS Changes</h3>
                <pre>{dns}</pre>
                <h3>HTTP Evidence</h3>
                <pre>{http}</pre>
            </div>
            """.format(
                seized=" seized" if result.is_seized else "",
                domain=result.domain,
                status="SEIZED" if result.is_seized else "No seizure detected",
                agency=f"<p>Seizing Agency: {result.agency}</p>" if result.agency else "",
                evidence="\n".join(f"<p class='evidence'>{e}</p>" for e in result.evidence),
                whois=json.dumps(result.whois_changes, indent=2),
                dns=json.dumps(result.dns_changes, indent=2),
                http=json.dumps(result.http_evidence, indent=2)
            )

        html += """
        </body>
        </html>
        """
        return html

def main():
    tool = SeizureDetector()
    return tool.main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1) 