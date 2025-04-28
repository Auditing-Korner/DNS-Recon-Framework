"""DNS server discovery and analysis tool for RFS DNS Framework."""

from typing import Dict, List, Any, Optional, Set
import socket
import dns.resolver
import dns.query
import dns.message
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .base_tool import BaseTool, ToolResult
from .utils import (
    detect_dns_server,
    get_domain_nameservers,
    get_ptr_record,
    check_dns_server_access
)

TOOL_CONFIG = {
    'name': 'find_server',
    'description': 'Discover and analyze DNS servers',
    'critical': True,
    'requires_root': False,
    'order': 2
}

class FindServerTool(BaseTool):
    """DNS server discovery tool implementation."""
    
    def __init__(self):
        super().__init__(TOOL_CONFIG['name'], TOOL_CONFIG['description'])
        self.requires_root = TOOL_CONFIG['requires_root']
        self.critical = TOOL_CONFIG['critical']

    def validate_args(self, **kwargs) -> List[str]:
        """Validate tool arguments."""
        errors = []
        
        if not kwargs.get('domain'):
            errors.append("Domain is required")
            
        ports = kwargs.get('ports', '').split(',')
        try:
            [int(port) for port in ports if port]
        except ValueError:
            errors.append("Invalid port numbers specified")
            
        server_types = kwargs.get('server_types', 'all')
        valid_types = {'authoritative', 'recursive', 'all'}
        if server_types not in valid_types:
            errors.append(f"Invalid server type: {server_types}")
            
        return errors

    def run(self, domain: str, output_file: str, **kwargs) -> ToolResult:
        """Execute DNS server discovery."""
        start_time = datetime.now().isoformat()
        findings = []
        errors = []
        warnings = []
        raw_data = {
            'servers': [],
            'ports': [],
            'versions': {},
            'recursive_servers': []
        }
        
        try:
            # Get tool parameters
            ports = [int(p) for p in kwargs.get('ports', '53,853,5353').split(',')]
            server_types = kwargs.get('server_types', 'all')
            check_version = kwargs.get('check_version', True)
            
            # Get domain nameservers
            nameservers = get_domain_nameservers(domain)
            if not nameservers:
                warnings.append("Could not find authoritative nameservers")
            
            # Analyze each nameserver
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_server = {}
                
                # Check authoritative servers
                if server_types in ['authoritative', 'all']:
                    for ns in nameservers:
                        for port in ports:
                            future = executor.submit(
                                self._analyze_server,
                                ns,
                                port,
                                check_version,
                                True
                            )
                            future_to_server[future] = (ns, port, 'authoritative')
                
                # Check for recursive servers
                if server_types in ['recursive', 'all']:
                    recursive_servers = self._find_recursive_servers(domain)
                    raw_data['recursive_servers'] = recursive_servers
                    
                    for server in recursive_servers:
                        for port in ports:
                            future = executor.submit(
                                self._analyze_server,
                                server,
                                port,
                                check_version,
                                False
                            )
                            future_to_server[future] = (server, port, 'recursive')
                
                # Process results
                for future in as_completed(future_to_server):
                    server, port, server_type = future_to_server[future]
                    try:
                        result = future.result()
                        if result:
                            raw_data['servers'].append(result)
                            raw_data['ports'].append(port)
                            
                            if 'version' in result:
                                raw_data['versions'][server] = result['version']
                                
                            self._analyze_server_security(
                                result,
                                server_type,
                                findings
                            )
                    except Exception as e:
                        errors.append(f"Error analyzing {server}:{port}: {str(e)}")
            
            success = True
            
        except Exception as e:
            success = False
            errors.append(f"Server discovery failed: {str(e)}")
        
        end_time = datetime.now().isoformat()
        
        # Create and return result
        result = self.create_result(
            success=success,
            findings=findings,
            domain=domain,
            output_file=output_file,
            errors=errors,
            warnings=warnings,
            raw_data=raw_data,
            start_time=start_time,
            end_time=end_time
        )
        
        # Save results
        result.save_to_file()
        
        return result

    def _analyze_server(
        self,
        ip: str,
        port: int,
        check_version: bool,
        is_authoritative: bool
    ) -> Optional[Dict[str, Any]]:
        """Analyze a DNS server."""
        try:
            # Get server information
            info = detect_dns_server(ip, port)
            if not info or 'error' in info:
                return None
                
            # Get PTR record
            ptr = get_ptr_record(ip)
            if ptr:
                info['ptr'] = ptr
            
            # Check for open recursion if authoritative
            if is_authoritative:
                info['open_recursion'] = self._check_recursion(ip, port)
            
            return info
            
        except:
            return None

    def _find_recursive_servers(self, domain: str) -> List[str]:
        """Find recursive DNS servers."""
        recursive_servers = set()
        
        # Common DNS providers
        providers = [
            '8.8.8.8',  # Google
            '8.8.4.4',  # Google
            '1.1.1.1',  # Cloudflare
            '1.0.0.1',  # Cloudflare
            '9.9.9.9',  # Quad9
            '208.67.222.222',  # OpenDNS
            '208.67.220.220'   # OpenDNS
        ]
        
        for server in providers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.timeout = 1
                resolver.lifetime = 1
                
                # Try to resolve the domain
                resolver.resolve(domain, 'A')
                recursive_servers.add(server)
            except:
                continue
        
        return list(recursive_servers)

    def _check_recursion(self, ip: str, port: int) -> bool:
        """Check if a server allows recursive queries."""
        try:
            # Create a test query for a domain we control
            test_domain = f"test-recursion-{datetime.now().timestamp()}.com"
            query = dns.message.make_query(test_domain, 'A')
            
            # Try to get a recursive answer
            response = dns.query.udp(query, ip, port=port, timeout=2)
            
            # Check if server attempted recursion
            return (
                response.flags & dns.flags.RA and  # Recursion Available
                not response.flags & dns.flags.AA  # Not Authoritative Answer
            )
        except:
            return False

    def _analyze_server_security(
        self,
        server_info: Dict[str, Any],
        server_type: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze server security configuration."""
        
        # Check for version disclosure
        if 'version' in server_info:
            findings.append(self.create_finding(
                title="DNS Server Version Disclosure",
                description=f"Server {server_info['ip']} reveals version information: {server_info['version']}",
                risk_level="Medium",
                evidence={
                    'ip': server_info['ip'],
                    'version': server_info['version'],
                    'software': server_info.get('software', 'Unknown')
                },
                recommendations=[
                    "Disable version disclosure in DNS server configuration",
                    "Use access controls to restrict version queries"
                ]
            ))
        
        # Check for open recursion on authoritative servers
        if (
            server_type == 'authoritative' and
            server_info.get('open_recursion', False)
        ):
            findings.append(self.create_finding(
                title="Open DNS Recursion",
                description=f"Authoritative server {server_info['ip']} allows recursive queries",
                risk_level="High",
                evidence={
                    'ip': server_info['ip'],
                    'port': server_info['port']
                },
                recommendations=[
                    "Disable recursion on authoritative servers",
                    "Implement proper access controls for recursive queries",
                    "Separate recursive and authoritative DNS services"
                ]
            ))
        
        # Check for non-standard ports
        if server_info['port'] not in [53, 853]:
            findings.append(self.create_finding(
                title="Non-Standard DNS Port",
                description=f"Server {server_info['ip']} running on non-standard port {server_info['port']}",
                risk_level="Low",
                evidence={
                    'ip': server_info['ip'],
                    'port': server_info['port']
                },
                recommendations=[
                    "Review necessity of non-standard port usage",
                    "Document and monitor non-standard configurations"
                ]
            ))
        
        # Check for TCP fallback
        if server_info.get('protocol') == 'tcp':
            findings.append(self.create_finding(
                title="TCP DNS Service",
                description=f"Server {server_info['ip']} supports TCP DNS queries",
                risk_level="Info",
                evidence={
                    'ip': server_info['ip'],
                    'port': server_info['port'],
                    'protocol': 'tcp'
                }
            ))

def main():
    """Tool entry point."""
    tool = FindServerTool()
    return tool 