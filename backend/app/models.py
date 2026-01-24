from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List, Literal
from enum import Enum


class AnalysisMode(str, Enum):
    """Analysis mode for the request"""
    BACKEND_EXTRACT = "backend_extract"
    CLIENT_EXTRACTED = "client_extracted"


class AnalyzeOptions(BaseModel):
    """Optional configuration for analysis"""
    strict_no_store: bool = Field(default=True, description="Never store raw plan data")
    max_findings: int = Field(default=50, description="Maximum number of risk findings to return")


class AnalyzeRequest(BaseModel):
    """Request model for /analyze endpoint"""
    plan_json: Dict[str, Any] = Field(..., description="Terraform plan JSON from 'terraform show -json tfplan'")
    mode: AnalysisMode = Field(default=AnalysisMode.BACKEND_EXTRACT, description="Analysis mode")
    options: Optional[AnalyzeOptions] = Field(default=None, description="Optional analysis configuration")


class Severity(str, Enum):
    """Risk severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFinding(BaseModel):
    """A single risk finding from the rule engine"""
    risk_id: str = Field(..., description="Stable rule identifier (e.g., SG-OPEN-INGRESS)")
    title: str = Field(..., description="Human-readable risk title")
    severity: Severity = Field(..., description="Risk severity level")
    resource_type: Optional[str] = Field(None, description="AWS resource type (e.g., aws_security_group)")
    resource_ref: str = Field(..., description="Hashed reference to resource address")
    evidence: Dict[str, Any] = Field(..., description="Safe evidence tokens (no raw values)")
    recommendation: str = Field(..., description="Remediation guidance")
    suggested_fix: Optional[str] = Field(None, description="Terraform (HCL) snippet to fix the issue")
    changed_paths: Optional[List[str]] = Field(None, description="Attribute paths that changed")


class ResourceChange(BaseModel):
    """Minimal representation of a resource change (diff skeleton)"""
    resource_type: str = Field(..., description="e.g., aws_security_group")
    action: str = Field(..., description="create/update/delete/replace")
    changed_paths: List[str] = Field(default_factory=list, description="Attribute paths that changed")
    resource_id_hash: str = Field(..., description="Stable hash of resource address")
    resource_address: Optional[str] = Field(None, description="Original resource address (for frontend display only, not sent to LLM)")


class PlanSummary(BaseModel):
    """High-level summary of the Terraform plan"""
    total_changes: int = Field(..., description="Total number of resource changes")
    creates: int = Field(default=0, description="Number of resources to create")
    updates: int = Field(default=0, description="Number of resources to update")
    deletes: int = Field(default=0, description="Number of resources to delete")
    replaces: int = Field(default=0, description="Number of resources to replace")
    terraform_version: Optional[str] = Field(None, description="Terraform version used")


class BedrockExplanation(BaseModel):
    """Structured explanation from Bedrock"""
    executive_summary: List[str] = Field(..., description="2-5 bullet points")
    plain_english_changes: str = Field(..., description="Grouped by resource type/action")
    top_risks_explained: str = Field(..., description="Explanation of critical risks")
    review_questions: List[str] = Field(..., description="What to double-check")


class AnalyzeResponse(BaseModel):
    """Response model for /analyze endpoint"""
    summary: PlanSummary = Field(..., description="High-level plan summary")
    diff_skeleton: List[ResourceChange] = Field(..., description="Minimal resource change representation")
    risk_findings: List[RiskFinding] = Field(..., description="Deterministic risk findings")
    explanation: BedrockExplanation = Field(..., description="Plain-English explanation from Bedrock")
    pr_comment: str = Field(..., description="Copy-paste ready PR comment text")
    session_id: Optional[str] = Field(None, description="Session ID for sharing/viewing full results")
