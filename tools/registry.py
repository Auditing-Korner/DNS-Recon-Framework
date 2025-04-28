"""Tool registry for RFS DNS Framework."""

import os
import importlib.util
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path

class ToolRegistry:
    """Registry for managing DNS recon tools."""

    def __init__(self):
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.loaded = False
        self.required_config_fields = {
            'name',
            'description',
            'critical',
            'requires_root',
            'order'
        }
        self.tool_dependencies: Dict[str, Set[str]] = {}
        self.logger = logging.getLogger(__name__)

    def register_tool(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Register a tool with the registry.
        
        Args:
            name: Tool name
            config: Tool configuration
            
        Returns:
            bool: True if registration successful
        """
        # Validate configuration
        missing_fields = self.required_config_fields - set(config.keys())
        if missing_fields:
            self.logger.error(f"Tool {name} missing required fields: {missing_fields}")
            return False
            
        # Check for duplicate registration
        if name in self.tools:
            self.logger.warning(f"Tool {name} already registered, updating configuration")
            
        # Store tool configuration
        self.tools[name] = config
        self.logger.debug(f"Successfully registered tool: {name}")
        return True

    def get_tool(self, name: str) -> Optional[Any]:
        """
        Get a tool module by name.
        
        Args:
            name: Tool name
            
        Returns:
            Optional[Any]: Tool module if found and loaded successfully
        """
        tool_config = self.tools.get(name)
        if not tool_config:
            self.logger.error(f"Tool {name} not found in registry")
            return None

        try:
            # Get tool file path
            tool_file = tool_config.get('file')
            if not tool_file:
                self.logger.error(f"No file path specified for tool {name}")
                return None

            # Check if tool file exists
            if not os.path.exists(tool_file):
                self.logger.error(f"Tool file not found: {tool_file}")
                return None
                
            # Load tool module
            spec = importlib.util.spec_from_file_location(name, tool_file)
            if not spec or not spec.loader:
                self.logger.error(f"Could not create module spec for {name}")
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Validate tool class
            tool_class_name = f"{name.title()}Tool"
            if not hasattr(module, tool_class_name):
                self.logger.error(f"Tool class {tool_class_name} not found in {name}")
                return None
                
            return module
            
        except ImportError as e:
            self.logger.error(f"Error importing tool {name}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error loading tool {name}: {str(e)}")
            
        return None

    def get_tool_config(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get a tool's configuration.
        
        Args:
            name: Tool name
            
        Returns:
            Optional[Dict[str, Any]]: Tool configuration if found
        """
        config = self.tools.get(name)
        if not config:
            self.logger.warning(f"No configuration found for tool {name}")
        return config

    def list_tools(self) -> List[Dict[str, Any]]:
        """
        List all registered tools.
        
        Returns:
            List[Dict[str, Any]]: List of tool configurations
        """
        if not self.loaded:
            self.discover_tools()
            
        return [
            {
                'name': name,
                'description': config['description'],
                'critical': config['critical'],
                'requires_root': config['requires_root'],
                'order': config['order'],
                'loaded': self.get_tool(name) is not None,
                'dependencies': list(self.tool_dependencies.get(name, set()))
            }
            for name, config in self.tools.items()
        ]

    def get_ordered_tools(self) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Get tools ordered by their execution order and dependencies.
        
        Returns:
            List[Tuple[str, Dict[str, Any]]]: Ordered list of (name, config) pairs
        """
        if not self.loaded:
            self.discover_tools()
            
        # Sort by order first
        ordered = sorted(
            self.tools.items(),
            key=lambda x: (x[1].get('order', 999), x[0])
        )
        
        # Respect dependencies
        final_order = []
        processed = set()
        
        def add_with_deps(tool_name: str):
            if tool_name in processed:
                return
            
            # Add dependencies first
            for dep in self.tool_dependencies.get(tool_name, set()):
                if dep not in processed:
                    add_with_deps(dep)
            
            # Add the tool
            tool_config = self.tools.get(tool_name)
            if tool_config:
                final_order.append((tool_name, tool_config))
                processed.add(tool_name)
        
        # Process all tools
        for name, _ in ordered:
            add_with_deps(name)
            
        return final_order

    def discover_tools(self, tools_dir: str = 'tools') -> None:
        """
        Discover and register tools from the tools directory.
        
        Args:
            tools_dir: Directory containing tool modules
        """
        if self.loaded:
            return

        tools_path = Path(tools_dir)
        if not tools_path.exists():
            self.logger.error(f"Tools directory not found: {tools_dir}")
            return

        # Register core tools first
        self._register_core_tools()

        # Discover additional tools
        for item in tools_path.glob('*.py'):
            if item.stem in ['__init__', 'base_tool', 'registry', 'utils']:
                continue

            try:
                # Load module
                spec = importlib.util.spec_from_file_location(item.stem, str(item))
                if not spec or not spec.loader:
                    self.logger.warning(f"Could not create module spec for {item.stem}")
                    continue
                    
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Check for tool configuration
                if hasattr(module, 'TOOL_CONFIG'):
                    config = module.TOOL_CONFIG.copy()
                    config['file'] = str(item)
                    
                    # Extract dependencies if defined
                    if hasattr(module, 'TOOL_DEPENDENCIES'):
                        self.tool_dependencies[item.stem] = set(module.TOOL_DEPENDENCIES)
                    
                    # Register the tool
                    if self.register_tool(item.stem, config):
                        self.logger.info(f"Registered tool: {item.stem}")
                    else:
                        self.logger.warning(f"Failed to register tool: {item.stem}")
                else:
                    self.logger.warning(f"No TOOL_CONFIG found in {item.stem}")
                    
            except Exception as e:
                self.logger.error(f"Error loading tool {item.stem}: {str(e)}")

        self.loaded = True
        self.logger.info(f"Discovered {len(self.tools)} tools")

    def _register_core_tools(self) -> None:
        """Register built-in core tools."""
        core_tools = {
            'dns_enum': {
                'name': 'dns_enum',
                'description': 'DNS enumeration and reconnaissance',
                'critical': True,
                'requires_root': False,
                'order': 1,
                'file': os.path.join('tools', 'dns_enum.py')
            },
            'find_server': {
                'name': 'find_server',
                'description': 'Discover and analyze DNS servers',
                'critical': True,
                'requires_root': False,
                'order': 2,
                'file': os.path.join('tools', 'find_server.py')
            },
            'zone_walker': {
                'name': 'zone_walker',
                'description': 'DNS zone transfer and walking',
                'critical': True,
                'requires_root': False,
                'order': 3,
                'file': os.path.join('tools', 'zone_walker.py')
            },
            'tld_brute': {
                'name': 'tld_brute',
                'description': 'TLD bruteforce scanner',
                'critical': False,
                'requires_root': False,
                'order': 4,
                'file': os.path.join('tools', 'tld_brute.py')
            },
            'dns_takeover': {
                'name': 'dns_takeover',
                'description': 'DNS takeover vulnerability scanner',
                'critical': True,
                'requires_root': False,
                'order': 5,
                'file': os.path.join('tools', 'dns_takeover.py')
            },
            'cloud_enum': {
                'name': 'cloud_enum',
                'description': 'Cloud service enumeration',
                'critical': False,
                'requires_root': False,
                'order': 6,
                'file': os.path.join('tools', 'cloud_enum.py')
            },
            'ssl_scanner': {
                'name': 'ssl_scanner',
                'description': 'SSL/TLS configuration scanner',
                'critical': False,
                'requires_root': False,
                'order': 7,
                'file': os.path.join('tools', 'ssl_scanner.py')
            }
        }
        
        for name, config in core_tools.items():
            if os.path.exists(config['file']):
                if self.register_tool(name, config):
                    self.logger.info(f"Registered core tool: {name}")
            else:
                self.logger.warning(f"Core tool file not found: {config['file']}")

# Create global registry instance
registry = ToolRegistry()

# Convenience functions
def list_tools() -> List[Dict[str, Any]]:
    """List all registered tools."""
    return registry.list_tools()

def get_tool(name: str):
    """Get a tool module by name."""
    return registry.get_tool(name)

def get_tool_config(name: str) -> Optional[Dict[str, Any]]:
    """Get a tool's configuration."""
    return registry.get_tool_config(name)

def get_ordered_tools() -> List[Tuple[str, Dict[str, Any]]]:
    """Get tools in execution order."""
    return registry.get_ordered_tools() 