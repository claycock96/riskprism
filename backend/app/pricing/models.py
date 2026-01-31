"""
Cost Estimation Models.

Pydantic models for resource cost estimation.
"""

from pydantic import BaseModel, Field


class ResourceCost(BaseModel):
    """Cost estimate for a single resource."""

    resource_ref: str = Field(..., description="Hashed resource reference")
    resource_type: str = Field(..., description="AWS resource type (e.g., aws_instance)")
    resource_address: str | None = Field(None, description="Original resource address for display")
    monthly_cost: float = Field(..., description="Estimated monthly cost in USD")
    hourly_cost: float | None = Field(None, description="Hourly rate if applicable")
    confidence: str = Field(..., description="Confidence level: high (lookup), medium (LLM), low (guess)")
    pricing_unit: str = Field(..., description="Pricing unit (e.g., per hour, per GB-month)")
    notes: str | None = Field(None, description="Additional context about the estimate")
    action: str = Field(..., description="Resource action: create, update, delete, replace")


class CostEstimate(BaseModel):
    """Cost estimate for an entire Terraform plan."""

    total_monthly_cost: float = Field(..., description="Total estimated monthly cost in USD")
    previous_monthly_cost: float | None = Field(None, description="Previous monthly cost (for updates/replaces)")
    net_change: float | None = Field(None, description="Net cost change (positive = increase)")
    percent_change: float | None = Field(None, description="Percent change from previous cost")
    resource_costs: list[ResourceCost] = Field(default_factory=list, description="Per-resource cost breakdown")
    currency: str = Field(default="USD", description="Currency code")
    estimation_method: str = Field(..., description="Method used: lookup, hybrid, or llm_only")
    pricing_region: str = Field(default="us-gov-west-1", description="AWS region used for pricing baseline")
    last_pricing_update: str = Field(..., description="ISO date when pricing data was last updated")
    resources_estimated: int = Field(0, description="Number of resources with cost estimates")
    resources_unknown: int = Field(0, description="Number of resources without estimates")
