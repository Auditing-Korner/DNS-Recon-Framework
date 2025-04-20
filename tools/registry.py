#!/usr/bin/env python3
"""
Tool Registry for RFS DNS Framework
Manages tool registration, configuration, and loading
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any

# Tool registry
_TOOLS = {
    "dns_enum": {
        "name": "dns_enum",
        "description": "Comprehensive DNS enumeration and analysis",
        "file": "dns_enum.py",
        "critical": True,
        "requires_root": False,
        "order": 1,
        "loaded": False
    },
    "find_server": {
        "name": "find_server",
        "description": "Discover and test DNS servers",
        "file": "find_dnsserver.py",
        "critical": True,
        "requires_root": False,
        "order": 2,
        "loaded": False
    },
    "cloud_enum": {
        "name": "cloud_enum",
        "description": "Detect and analyze cloud service providers",
        "file": "enumerate_cloud_providers.py",
        "critical": False,
        "requires_root": False,
        "order": 3,
        "loaded": False
    },
    "tld_brute": {
        "name": "tld_brute",
        "description": "Multi-threaded TLD discovery",
        "file": "dns_tld_bruteforce.py",
        "critical": False,
        "requires_root": False,
        "order": 4,
        "loaded": False
    },
    "takeover": {
        "name": "takeover",
        "description": "Identify subdomain takeover vulnerabilities",
        "file": "dns_takeover_scanner.py",
        "critical": True,
        "requires_root": False,
        "order": 5,
        "loaded": False
    },
    "seizure": {
        "name": "seizure",
        "description": "Identify law enforcement domain seizures",
        "file": "seizure_detector.py",
        "critical": True,
        "requires_root": False,
        "order": 6,
        "loaded": False
    },
    "mobile_gw": {
        "name": "mobile_gw",
        "description": "Enumerate 3GPP Mobile Gateways",
        "file": "mobile_gateway_enum.py",
        "critical": True,
        "requires_root": False,
        "order": 7,
        "loaded": False
    },
    "cache_poison": {
        "name": "cache_poison",
        "description": "DNS cache poisoning detection",
        "file": "dns_cache_poison.py",
        "critical": True,
        "requires_root": True,
        "order": 8,
        "loaded": False
    },
    "ssl_scanner": {
        "name": "ssl_scanner",
        "description": "SSL/TLS security scanner",
        "file": "ssl_scanner.py",
        "critical": True,
        "requires_root": False,
        "order": 9,
        "loaded": False
    },
    "dns_takeover": {
        "name": "dns_takeover",
        "description": "DNS subdomain takeover vulnerability scanner",
        "file": "dns_takeover_scanner.py",
        "critical": True,
        "requires_root": False,
        "order": 10,
        "loaded": False
    },
    "subdomain_takeover": {
        "name": "subdomain_takeover",
        "description": "Advanced Subdomain Takeover Testing Tool",
        "file": "subdomain_takeover_tester.py",
        "critical": True,
        "requires_root": False,
        "order": 11,
        "loaded": False
    },
    "zone_walker": {
        "name": "zone_walker",
        "description": "DNSSEC Zone Walking and NSEC/NSEC3 Analysis",
        "file": "dns_zone_walker.py",
        "critical": True,
        "requires_root": False,
        "order": 12,
        "loaded": False
    },
    "tunnel_detector": {
        "name": "tunnel_detector",
        "description": "Detect DNS Tunneling and Data Exfiltration",
        "file": "dns_tunnel_detector.py",
        "critical": True,
        "requires_root": True,
        "order": 13,
        "loaded": False
    },
    "amp_tester": {
        "name": "amp_tester",
        "description": "DNS Amplification and Reflection Vulnerability Testing",
        "file": "dns_amp_tester.py",
        "critical": True,
        "requires_root": True,
        "order": 14,
        "loaded": False
    },
    "privacy_scanner": {
        "name": "privacy_scanner",
        "description": "DNS Privacy, DoH, DoT, and DNSCrypt Testing",
        "file": "dns_privacy_scanner.py",
        "critical": False,
        "requires_root": False,
        "order": 15,
        "loaded": False
    },
    "config_auditor": {
        "name": "config_auditor",
        "description": "DNS Configuration and Security Best Practices Analysis",
        "file": "dns_config_auditor.py",
        "critical": True,
        "requires_root": False,
        "order": 16,
        "loaded": False
    }
}

def list_tools() -> List[Dict[str, Any]]:
    """Return list of all registered tools"""
    return [tool for tool in _TOOLS.values()]

def get_tool(name: str) -> Optional[Any]:
    """Get tool module by name"""
    if name not in _TOOLS:
        return None
        
    if _TOOLS[name]['loaded']:
        return sys.modules.get(f"tools.{name}")
        
    # Try to load the tool
    try:
        tool_path = Path(__file__).parent / _TOOLS[name]['file']
        if not tool_path.exists():
            return None
            
        spec = importlib.util.spec_from_file_location(
            f"tools.{name}",
            tool_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        _TOOLS[name]['loaded'] = True
        return module
        
    except Exception as e:
        print(f"Error loading tool {name}: {e}")
        return None

def get_tool_config(name: str) -> Optional[Dict]:
    """Get tool configuration by name"""
    return _TOOLS.get(name)

def register_tool(name: str, config: Dict) -> bool:
    """Register a new tool"""
    if name in _TOOLS:
        return False
    _TOOLS[name] = config
    return True 