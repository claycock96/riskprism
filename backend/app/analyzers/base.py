"""
Base Analyzer Framework

Provides abstract base class for all security analyzers.
Each analyzer implements parsing, rule evaluation, and LLM sanitization.

PRIVACY MODEL:
- Each analyzer is responsible for sanitizing its own input type
- IAMPolicyAnalyzer: sanitize_for_llm() hashes ARNs, account IDs, resource names
- TerraformAnalyzer: Uses TerraformPlanParser which sanitizes during extraction
  (see parser.py for Terraform-specific sanitization logic)

All sanitize_for_llm() implementations must ensure NO raw identifiers, secrets,
or account-specific data reaches the LLM.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel

from app.models import RiskFinding


class AnalyzerType(str, Enum):
    """Supported analyzer types."""

    TERRAFORM = "terraform"
    IAM = "iam"


class AnalysisResult(BaseModel):
    """Standard result format for all analyzers."""

    analyzer_type: AnalyzerType
    summary: dict[str, Any]
    findings: list[RiskFinding]
    sanitized_payload: dict[str, Any]
    resource_hash_map: dict[str, str]  # hash -> original name (for frontend remapping)


class BaseAnalyzer(ABC):
    """
    Abstract base class for security analyzers.

    All analyzers must implement:
    - parse(): Validate and normalize input
    - analyze(): Run deterministic security rules
    - sanitize_for_llm(): Prepare privacy-safe payload for AI
    - generate_summary(): Create high-level statistics
    """

    analyzer_type: AnalyzerType

    @abstractmethod
    def parse(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """
        Parse and validate input data.

        Args:
            input_data: Raw input (e.g., Terraform plan JSON, IAM policy)

        Returns:
            Normalized/validated data structure

        Raises:
            ValueError: If input is invalid
        """
        pass

    @abstractmethod
    def analyze(self, parsed_data: dict[str, Any], max_findings: int = 50) -> list[RiskFinding]:
        """
        Run deterministic security rules against parsed data.

        Args:
            parsed_data: Output from parse()
            max_findings: Maximum number of findings to return

        Returns:
            List of security findings
        """
        pass

    @abstractmethod
    def sanitize_for_llm(self, parsed_data: dict[str, Any], findings: list[RiskFinding]) -> dict[str, Any]:
        """
        Create a sanitized payload safe to send to LLM.

        This should:
        - Hash sensitive identifiers (resource names, ARNs, account IDs)
        - Extract only structural information (no raw values)
        - Include evidence tokens from findings

        Args:
            parsed_data: Output from parse()
            findings: Output from analyze()

        Returns:
            Sanitized payload dict
        """
        pass

    @abstractmethod
    def generate_summary(self, parsed_data: dict[str, Any]) -> dict[str, Any]:
        """
        Generate high-level summary statistics.

        Args:
            parsed_data: Output from parse()

        Returns:
            Summary dict (format varies by analyzer type)
        """
        pass

    @abstractmethod
    def get_resource_hash_map(self) -> dict[str, str]:
        """
        Get the mapping of hashed references to original names.

        This is used by the frontend to remap hashed identifiers
        back to human-readable names.

        Returns:
            Dict mapping hash -> original identifier
        """
        pass
