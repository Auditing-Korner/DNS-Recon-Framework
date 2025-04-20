"""
RFS DNS Framework Tools Package
"""

from pathlib import Path
from typing import Dict, Any, Optional, List, Type, Tuple
import importlib.util
import sys
import logging
from .base_tool import BaseTool

# Make tools directory path available
TOOLS_DIR = Path(__file__).parent

class ToolRegistry:
    """Registry for all available tools"""
    
    def __init__(self):
        self._tools: Dict[str, Any] = {}
        self._tool_configs: Dict[str, Dict[str, Any]] = {}
        self._logger = logging.getLogger(__name__)
        self._load_tools()
    
    def _load_tools(self):
        """Load all tool modules"""
        tool_files = {
            'dns_enum': {
                'file': 'dns_enum.py',
                'description': 'Comprehensive DNS enumeration and analysis',
                'critical': True,
                'requires_root': False,
                'order': 1
            },
            'find_server': {
                'file': 'find_dnsserver.py',
                'description': 'Discover and test DNS servers',
                'critical': True,
                'requires_root': False,
                'order': 2
            },
            'cloud_enum': {
                'file': 'enumerate_cloud_providers.py',
                'description': 'Detect and analyze cloud service providers',
                'critical': False,
                'requires_root': False,
                'order': 3
            },
            'tld_brute': {
                'file': 'dns_tld_bruteforce.py',
                'description': 'Multi-threaded TLD discovery',
                'critical': False,
                'requires_root': False,
                'order': 4
            },
            'takeover': {
                'file': 'cloud_takeover_detector.py',
                'description': 'Identify subdomain takeover vulnerabilities',
                'critical': True,
                'requires_root': False,
                'order': 5
            },
            'seizure': {
                'file': 'seizure_detector.py',
                'description': 'Identify law enforcement domain seizures',
                'critical': True,
                'requires_root': False,
                'order': 6
            },
            'mobile_gw': {
                'file': 'mobile_gateway_enum.py',
                'description': 'Enumerate 3GPP Mobile Gateways',
                'critical': True,
                'requires_root': False,
                'order': 7
            },
            'cache_poison': {
                'file': 'dns_cache_poison.py',
                'description': 'DNS cache poisoning detection',
                'critical': True,
                'requires_root': True,
                'order': 8
            },
            'ssl_scanner': {
                'file': 'ssl_scanner.py',
                'description': 'SSL/TLS security scanner',
                'critical': True,
                'requires_root': False,
                'order': 9
            },
            'dns_takeover': {
                'file': 'dns_takeover_scanner.py',
                'description': 'DNS subdomain takeover vulnerability scanner',
                'critical': True,
                'requires_root': False,
                'order': 10
            }
        }
        
        for module_name, config in tool_files.items():
            file_path = TOOLS_DIR / config['file']
            if file_path.exists():
                try:
                    # Import module
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    
                    # Store module and config
                    self._tools[module_name] = module
                    self._tool_configs[module_name] = config
                    
                    self._logger.debug(f"Loaded tool: {module_name}")
                except Exception as e:
                    self._logger.error(f"Error loading {module_name}: {e}")
    
    def get_tool(self, name: str) -> Optional[Any]:
        """Get a tool module by name"""
        return self._tools.get(name)
    
    def get_tool_config(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a tool's configuration"""
        return self._tool_configs.get(name)
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """Get information about all loaded tools"""
        tools_info = []
        for name, module in self._tools.items():
            config = self._tool_configs.get(name, {})
            tools_info.append({
                'name': name,
                'description': config.get('description', 'No description'),
                'critical': config.get('critical', False),
                'requires_root': config.get('requires_root', False),
                'order': config.get('order', 999),
                'loaded': bool(module)
            })
        return sorted(tools_info, key=lambda x: x['order'])
    
    def get_ordered_tools(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Get tools sorted by execution order"""
        return sorted(
            [(name, self._tool_configs[name]) for name in self._tools],
            key=lambda x: x[1].get('order', 999)
        )

# Create global tool registry
registry = ToolRegistry()

# Export tools
dns_enum = registry.get_tool('dns_enum')
find_server = registry.get_tool('find_server')
cloud_enum = registry.get_tool('cloud_enum')
tld_brute = registry.get_tool('tld_brute')
takeover = registry.get_tool('takeover')
seizure = registry.get_tool('seizure')
mobile_gw = registry.get_tool('mobile_gw')
cache_poison = registry.get_tool('cache_poison')
ssl_scanner = registry.get_tool('ssl_scanner')
dns_takeover = registry.get_tool('dns_takeover')

__all__ = [
    'registry',
    'dns_enum',
    'find_server',
    'cloud_enum',
    'tld_brute',
    'takeover',
    'seizure',
    'mobile_gw',
    'cache_poison',
    'ssl_scanner',
    'dns_takeover'
] 