from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List, Literal
from enum import Enum
from datetime import datetime
import json
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.orm import DeclarativeBase


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


class AttributeDiff(BaseModel):
    """Represents a change in a single attribute"""
    path: str = Field(..., description="Attribute path (e.g., ingress.0.cidr_blocks)")
    before: Any = Field(None, description="Value before change")
    after: Any = Field(None, description="Value after change")


class ResourceChange(BaseModel):
    """Minimal representation of a resource change (diff skeleton)"""
    resource_type: str = Field(..., description="e.g., aws_security_group")
    action: str = Field(..., description="create/update/delete/replace")
    changed_paths: List[str] = Field(default_factory=list, description="Attribute paths that changed")
    attribute_diffs: List[AttributeDiff] = Field(default_factory=list, description="Detailed attribute changes")
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


class Base(DeclarativeBase):
    pass


class AnalysisSession(Base):
    """SQLAlchemy model for persistent session storage"""
    __tablename__ = "analysis_sessions"

    session_id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    accessed_at = Column(DateTime, default=datetime.utcnow)
    
    # Store complex objects as JSON strings
    summary_json = Column(Text, nullable=False)
    diff_skeleton_json = Column(Text, nullable=False)
    risk_findings_json = Column(Text, nullable=False)
    explanation_json = Column(Text, nullable=False)
    pr_comment = Column(Text, nullable=False)
    
    # Audit Logging
    user_ip = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    request_metadata_json = Column(Text, nullable=True)

    def to_analyze_response(self) -> AnalyzeResponse:
        """Convert ORM model back to Pydantic AnalyzeResponse"""
        return AnalyzeResponse(
            summary=PlanSummary(**json.loads(self.summary_json)),
            diff_skeleton=[
                ResourceChange(
                    **{**c, "attribute_diffs": [AttributeDiff(**d) for d in c.get("attribute_diffs", [])]}
                ) for c in json.loads(self.diff_skeleton_json)
            ],
            risk_findings=[RiskFinding(**f) for f in json.loads(self.risk_findings_json)],
            explanation=BedrockExplanation(**json.loads(self.explanation_json)),
            pr_comment=self.pr_comment,
            session_id=self.session_id
        )

    @classmethod
    def from_analyze_response(cls, response: AnalyzeResponse, session_id: str, 
                              user_ip: str = None, user_agent: str = None, 
                              request_metadata: Dict = None):
        """Create ORM model from Pydantic AnalyzeResponse"""
        return cls(
            session_id=session_id,
            summary_json=response.summary.model_dump_json(),
            diff_skeleton_json=json.dumps([c.model_dump() for c in response.diff_skeleton]),
            risk_findings_json=json.dumps([f.model_dump() for f in response.risk_findings]),
            explanation_json=response.explanation.model_dump_json(),
            pr_comment=response.pr_comment,
            user_ip=user_ip,
            user_agent=user_agent,
            request_metadata_json=json.dumps(request_metadata) if request_metadata else None
        )
