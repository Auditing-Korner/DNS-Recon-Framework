#!/usr/bin/env python3

import os
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from rich.console import Console

class ConfigManager:
    """Configuration manager for the RFS DNS Framework"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            # Look for config file in common locations
            config_paths = [
                self.config_file,
                os.path.expanduser("~/.rfs-dns/config.yaml"),
                "/etc/rfs-dns/config.yaml"
            ]
            
            config_file = None
            for path in config_paths:
                if os.path.exists(path):
                    config_file = path
                    break
            
            if not config_file:
                self.logger.warning(f"No configuration file found, using defaults")
                return self._load_default_config()
            
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
                
            self.logger.info(f"Loaded configuration from {config_file}")
            
            # Validate configuration
            self._validate_config()
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self.console.print(f"[red]Error loading configuration: {str(e)}")
            self._load_default_config()

    def _load_default_config(self) -> None:
        """Load default configuration"""
        default_config_file = os.path.join(os.path.dirname(__file__), "config.yaml")
        try:
            with open(default_config_file, 'r') as f:
                self.config = yaml.safe_load(f)
            self.logger.info("Loaded default configuration")
        except Exception as e:
            self.logger.error(f"Error loading default configuration: {str(e)}")
            self.config = self._get_minimal_config()

    def _get_minimal_config(self) -> Dict[str, Any]:
        """Return minimal working configuration"""
        return {
            "version": "2.1.0",
            "general": {
                "output_dir": "results",
                "default_report_format": "json",
                "max_threads": 10,
                "debug": False
            },
            "dns": {
                "resolvers": ["8.8.8.8", "1.1.1.1"],
                "query_timeout": 5
            },
            "logging": {
                "level": "INFO",
                "console_output": True
            }
        }

    def _validate_config(self) -> None:
        """Validate configuration values"""
        # Check version
        if "version" not in self.config:
            self.logger.warning("No version specified in config")
            self.config["version"] = "2.1.0"
        
        # Ensure required sections exist
        required_sections = ["general", "dns", "tools", "logging"]
        for section in required_sections:
            if section not in self.config:
                self.logger.warning(f"Missing {section} section in config")
                self.config[section] = {}
        
        # Validate general settings
        general = self.config["general"]
        if "max_threads" in general:
            try:
                general["max_threads"] = int(general["max_threads"])
                if general["max_threads"] < 1:
                    general["max_threads"] = 10
            except:
                general["max_threads"] = 10
        
        # Validate DNS settings
        dns = self.config["dns"]
        if "query_timeout" in dns:
            try:
                dns["query_timeout"] = float(dns["query_timeout"])
                if dns["query_timeout"] < 0:
                    dns["query_timeout"] = 5
            except:
                dns["query_timeout"] = 5

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        try:
            return self.config[section][key]
        except KeyError:
            return default

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

    def save(self, config_file: Optional[str] = None) -> bool:
        """Save current configuration to file"""
        try:
            save_path = config_file or self.config_file
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            
            self.logger.info(f"Configuration saved to {save_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
            return False

    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool"""
        return self.config.get("tools", {}).get(tool_name, {})

    def update_tool_config(self, tool_name: str, config: Dict[str, Any]) -> None:
        """Update configuration for a specific tool"""
        if "tools" not in self.config:
            self.config["tools"] = {}
        self.config["tools"][tool_name] = config

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        try:
            if service in ["aws", "azure", "gcp"]:
                return self.config["api_keys"][service]
            return self.config["api_keys"].get(service)
        except KeyError:
            return None

    def set_api_key(self, service: str, key: str) -> None:
        """Set API key for a service"""
        if "api_keys" not in self.config:
            self.config["api_keys"] = {}
        self.config["api_keys"][service] = key 