"""Base tool class for RFS DNS Framework."""

import logging
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import os
from datetime import datetime

@dataclass
class ToolResult:
    """Class to store and format tool execution results."""
    success: bool
    findings: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]
    start_time: str
    end_time: str
    tool_name: str
    domain: str
    output_file: str
    risk_summary: Dict[str, int]
    raw_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary format."""
        return {
            'success': self.success,
            'findings': self.findings,
            'errors': self.errors,
            'warnings': self.warnings,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'tool_name': self.tool_name,
            'domain': self.domain,
            'risk_summary': self.risk_summary,
            'raw_data': self.raw_data
        }

    def save_to_file(self) -> None:
        """Save the results to the specified output file."""
        if self.output_file:
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            with open(self.output_file, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)

class BaseTool(ABC):
    """Base class for all DNS recon tools."""
    
    def __init__(self, name: str, description: str):
        """
        Initialize the base tool.
        
        Args:
            name: Tool name
            description: Tool description
        """
        self.name = name
        self.description = description
        self.logger = logging.getLogger(name)
        self.findings = []
        self.requires_root = False
        self.critical = False
        self.sequential = False
        self.risk_levels = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }

    @abstractmethod
    def validate_args(self, args: Dict[str, Any]) -> bool:
        """
        Validate tool arguments.
        
        Args:
            args: Tool arguments
            
        Returns:
            bool: True if arguments are valid
        """
        pass
        
    @abstractmethod
    def run(self, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run the tool.
        
        Args:
            args: Tool arguments
            
        Returns:
            List[Dict[str, Any]]: Tool findings
        """
        pass
        
    def get_tool_config(self) -> Dict[str, Any]:
        """
        Get tool configuration.
        
        Returns:
            Dict[str, Any]: Tool configuration
        """
        return {
            'name': self.name,
            'description': self.description,
            'requires_root': self.requires_root,
            'critical': self.critical
        }
        
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """
        Add a finding to the tool's results.
        
        Args:
            finding: Finding to add
        """
        self.findings.append(finding)
        
    def clear_findings(self) -> None:
        """Clear all findings."""
        self.findings = []
        
    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings.
        
        Returns:
            List[Dict[str, Any]]: All findings
        """
        return self.findings

    def update_risk_summary(self, risk_level: str) -> None:
        """
        Update the risk level counters.
        
        Args:
            risk_level: Risk level to increment
        """
        if risk_level in self.risk_levels:
            self.risk_levels[risk_level] += 1

    def create_finding(
        self,
        title: str,
        description: str,
        risk_level: str,
        evidence: Optional[Dict[str, Any]] = None,
        recommendations: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a standardized finding entry.
        
        Args:
            title: Finding title
            description: Detailed description
            risk_level: Risk level (Critical, High, Medium, Low, Info)
            evidence: Supporting evidence/data
            recommendations: List of remediation steps
            
        Returns:
            Dict[str, Any]: Formatted finding
        """
        self.update_risk_summary(risk_level)
        
        return {
            'title': title,
            'description': description,
            'risk_level': risk_level,
            'evidence': evidence or {},
            'recommendations': recommendations or [],
            'timestamp': datetime.now().isoformat()
        }

    def create_result(
        self,
        success: bool,
        findings: List[Dict[str, Any]],
        domain: str,
        output_file: str,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> ToolResult:
        """
        Create a standardized tool result.
        
        Args:
            success: Whether the tool executed successfully
            findings: List of findings
            domain: Target domain
            output_file: Path to save results
            errors: List of errors encountered
            warnings: List of warnings
            raw_data: Additional tool-specific data
            start_time: Tool start time (ISO format)
            end_time: Tool end time (ISO format)
            
        Returns:
            ToolResult: Formatted tool result
        """
        return ToolResult(
            success=success,
            findings=findings,
            errors=errors or [],
            warnings=warnings or [],
            start_time=start_time or datetime.now().isoformat(),
            end_time=end_time or datetime.now().isoformat(),
            tool_name=self.name,
            domain=domain,
            output_file=output_file,
            risk_summary=self.risk_levels.copy(),
            raw_data=raw_data or {}
        ) 