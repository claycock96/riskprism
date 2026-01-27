"""
RiskPrism: Terraform

Implements the BaseAnalyzer interface for Terraform plan JSON analysis.
Wraps existing parser.py and risk_engine.py functionality.
"""

from typing import Dict, Any, List
import logging

from .base import BaseAnalyzer, AnalyzerType
from app.parser import TerraformPlanParser
from app.risk_engine import RiskEngine
from app.models import RiskFinding, PlanSummary, ResourceChange

logger = logging.getLogger(__name__)


class TerraformAnalyzer(BaseAnalyzer):
    """
    RiskPrism: Terraform.
    
    Analyzes Terraform plan JSON for security risks using:
    - Deterministic rule engine (14+ rules)
    - Resource address hashing for privacy
    - Diff skeleton extraction for LLM context
    """
    
    analyzer_type = AnalyzerType.TERRAFORM
    
    def __init__(self):
        self.parser = TerraformPlanParser()
        self.risk_engine = RiskEngine()
        self._resource_hash_map: Dict[str, str] = {}
        self._diff_skeleton: List[ResourceChange] = []
    
    def parse(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and validate Terraform plan JSON.
        
        Args:
            input_data: Raw Terraform plan JSON
            
        Returns:
            Validated plan structure
        """
        parsed = self.parser.parse(input_data)
        
        # Extract diff skeleton (this also builds the hash map)
        self._diff_skeleton = self.parser.extract_diff_skeleton(parsed)
        
        # Build hash map for frontend remapping
        self._resource_hash_map = {
            change.resource_ref: change.resource_address
            for change in self._diff_skeleton
        }
        
        return parsed
    
    def analyze(
        self, 
        parsed_data: Dict[str, Any],
        max_findings: int = 50
    ) -> List[RiskFinding]:
        """
        Run Terraform security rules.
        
        Args:
            parsed_data: Validated Terraform plan
            max_findings: Maximum findings to return
            
        Returns:
            List of security findings
        """
        return self.risk_engine.analyze(
            parsed_data,
            self._diff_skeleton,
            max_findings=max_findings
        )
    
    def sanitize_for_llm(
        self, 
        parsed_data: Dict[str, Any],
        findings: List[RiskFinding]
    ) -> Dict[str, Any]:
        """
        Create sanitized payload for LLM.
        
        Includes:
        - Summary statistics
        - Diff skeleton (hashed resource refs, no values)
        - Risk findings with evidence tokens
        """
        summary = self.generate_summary(parsed_data)
        
        return {
            "analyzer_type": self.analyzer_type.value,
            "summary": summary.model_dump() if hasattr(summary, 'model_dump') else summary,
            "diff_skeleton": [item.model_dump() for item in self._diff_skeleton],
            "risk_findings": [finding.model_dump() for finding in findings],
        }
    
    def generate_summary(self, parsed_data: Dict[str, Any]) -> PlanSummary:
        """
        Generate Terraform plan summary statistics.
        """
        return self.parser.generate_summary(parsed_data)
    
    def get_resource_hash_map(self) -> Dict[str, str]:
        """
        Get hash -> resource address mapping.
        """
        return self._resource_hash_map
    
    def calculate_plan_hash(self) -> str:
        """
        Calculate fingerprint for caching.
        """
        return self.parser.calculate_plan_hash(self._diff_skeleton)
    
    def get_diff_skeleton(self) -> List[ResourceChange]:
        """
        Get the extracted diff skeleton.
        """
        return self._diff_skeleton
