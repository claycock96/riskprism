"""
Cost Estimator Engine.

Estimates monthly costs for Terraform plan resources using:
1. Static pricing database lookups (high confidence)
2. LLM fallback for unknown resources (medium confidence)
"""

import logging
from typing import Any

from app.models import ResourceChange

from .aws_pricing import (
    PRICING_LAST_UPDATED,
    PRICING_REGION,
    get_resource_pricing_info,
)
from .models import CostEstimate, ResourceCost

logger = logging.getLogger(__name__)


class CostEstimator:
    """
    Estimates costs for Terraform plan resources.

    Uses a hybrid approach:
    - Static pricing database for common AWS resources
    - LLM fallback for unknown resource types
    """

    def __init__(self, llm_client: Any | None = None):
        """
        Initialize cost estimator.

        Args:
            llm_client: Optional LLMClient for fallback estimates
        """
        self.llm_client = llm_client

    def estimate_plan_cost(
        self,
        diff_skeleton: list[ResourceChange],
        parsed_plan: dict[str, Any],
        use_llm_fallback: bool = True,
    ) -> CostEstimate:
        """
        Calculate cost estimates for all resources in a Terraform plan.

        Args:
            diff_skeleton: List of resource changes from the parser
            parsed_plan: Full parsed Terraform plan with resource attributes
            use_llm_fallback: Whether to use LLM for unknown resources

        Returns:
            CostEstimate with per-resource and total costs
        """
        resource_costs: list[ResourceCost] = []
        total_new_cost = 0.0
        total_previous_cost = 0.0
        resources_estimated = 0
        resources_unknown = 0
        used_llm = False

        # Build lookup from address to resource change details
        resource_changes_map = self._build_resource_map(parsed_plan)

        for resource in diff_skeleton:
            resource_type = resource.resource_type
            resource_address = resource.resource_address or resource.resource_ref
            action = resource.action

            # Get resource attributes from the plan
            attributes = self._get_resource_attributes(resource_address, resource_changes_map, action)
            before_attributes = self._get_before_attributes(resource_address, resource_changes_map)

            # Calculate cost for this resource
            cost_info = get_resource_pricing_info(resource_type, attributes)

            if cost_info is not None:
                # Successful lookup
                monthly_cost = cost_info["monthly_cost"]
                hourly_cost = cost_info.get("hourly_cost")
                confidence = cost_info["confidence"]
                pricing_unit = cost_info["pricing_unit"]
                notes = cost_info.get("notes")
                resources_estimated += 1
            else:
                # Unknown resource type
                resources_unknown += 1

                if use_llm_fallback and self.llm_client:
                    # LLM fallback (would be async in production)
                    cost_info = self._estimate_with_llm(resource_type, attributes)
                    if cost_info:
                        monthly_cost = cost_info["monthly_cost"]
                        hourly_cost = cost_info.get("hourly_cost")
                        confidence = "medium"
                        pricing_unit = cost_info.get("pricing_unit", "estimated")
                        notes = f"LLM estimate: {cost_info.get('notes', 'Based on similar resources')}"
                        used_llm = True
                        resources_estimated += 1
                        resources_unknown -= 1
                    else:
                        # LLM also couldn't estimate
                        monthly_cost = 0.0
                        hourly_cost = None
                        confidence = "low"
                        pricing_unit = "unknown"
                        notes = f"Unable to estimate cost for {resource_type}"
                else:
                    # No LLM fallback
                    monthly_cost = 0.0
                    hourly_cost = None
                    confidence = "low"
                    pricing_unit = "unknown"
                    notes = f"Resource type not in pricing database: {resource_type}"

            # Calculate previous cost for updates/replaces
            previous_cost = 0.0
            if action in ("update", "replace") and before_attributes:
                before_cost_info = get_resource_pricing_info(resource_type, before_attributes)
                if before_cost_info:
                    previous_cost = before_cost_info["monthly_cost"]

            # Handle action-specific cost calculations
            if action == "delete":
                # Deleting reduces cost
                total_previous_cost += monthly_cost
                monthly_cost = 0.0
            elif action == "create":
                # Creating adds new cost
                total_new_cost += monthly_cost
            elif action in ("update", "replace"):
                # Update/replace: new cost replaces old
                total_previous_cost += previous_cost
                total_new_cost += monthly_cost
            else:
                # No-op or read
                total_new_cost += monthly_cost
                total_previous_cost += monthly_cost

            resource_costs.append(
                ResourceCost(
                    resource_ref=resource.resource_ref or "",
                    resource_type=resource_type,
                    resource_address=resource_address,
                    monthly_cost=monthly_cost,
                    hourly_cost=hourly_cost,
                    confidence=confidence,
                    pricing_unit=pricing_unit,
                    notes=notes,
                    action=action,
                )
            )

        # Calculate percent change
        percent_change = None
        net_change = None
        if total_previous_cost > 0:
            net_change = total_new_cost - total_previous_cost
            percent_change = ((total_new_cost - total_previous_cost) / total_previous_cost) * 100

        # Determine estimation method
        if resources_unknown == 0:
            estimation_method = "lookup"
        elif used_llm:
            estimation_method = "hybrid"
        else:
            estimation_method = "lookup"

        return CostEstimate(
            total_monthly_cost=round(total_new_cost, 2),
            previous_monthly_cost=round(total_previous_cost, 2) if total_previous_cost > 0 else None,
            net_change=round(net_change, 2) if net_change is not None else None,
            percent_change=round(percent_change, 1) if percent_change is not None else None,
            resource_costs=resource_costs,
            currency="USD",
            estimation_method=estimation_method,
            pricing_region=PRICING_REGION,
            last_pricing_update=PRICING_LAST_UPDATED,
            resources_estimated=resources_estimated,
            resources_unknown=resources_unknown,
        )

    def _build_resource_map(self, parsed_plan: dict[str, Any]) -> dict[str, dict]:
        """Build a map of resource address to resource change details."""
        resource_map = {}
        for change in parsed_plan.get("resource_changes", []):
            address = change.get("address", "")
            resource_map[address] = change
        return resource_map

    def _get_resource_attributes(self, address: str, resource_map: dict[str, dict], action: str) -> dict[str, Any]:
        """
        Get resource attributes from the plan.

        For creates/updates, uses 'after' attributes.
        For deletes, uses 'before' attributes.
        """
        if address not in resource_map:
            return {}

        change = resource_map[address].get("change", {})

        if action == "delete":
            return change.get("before", {}) or {}
        else:
            return change.get("after", {}) or {}

    def _get_before_attributes(self, address: str, resource_map: dict[str, dict]) -> dict[str, Any]:
        """Get 'before' attributes for calculating previous cost."""
        if address not in resource_map:
            return {}

        change = resource_map[address].get("change", {})
        return change.get("before", {}) or {}

    def _estimate_with_llm(self, resource_type: str, attributes: dict[str, Any]) -> dict[str, Any] | None:
        """
        Fallback to LLM for cost estimation of unknown resources.

        This is a placeholder - in production, this would make an async call
        to the LLM client with a specific pricing prompt.
        """
        # For now, return None to indicate no estimate available
        # A full implementation would:
        # 1. Build a prompt with the resource type and key attributes
        # 2. Ask the LLM for an estimated monthly cost
        # 3. Parse and validate the response
        logger.debug(f"LLM fallback requested for {resource_type} (not yet implemented)")
        return None


# Convenience function for estimating a single resource
def estimate_resource_cost(resource_type: str, attributes: dict[str, Any]) -> ResourceCost | None:
    """
    Estimate cost for a single resource.

    Args:
        resource_type: AWS resource type
        attributes: Resource attributes

    Returns:
        ResourceCost or None if unable to estimate
    """
    cost_info = get_resource_pricing_info(resource_type, attributes)

    if cost_info is None:
        return None

    return ResourceCost(
        resource_ref="",
        resource_type=resource_type,
        resource_address=None,
        monthly_cost=cost_info["monthly_cost"],
        hourly_cost=cost_info.get("hourly_cost"),
        confidence=cost_info["confidence"],
        pricing_unit=cost_info["pricing_unit"],
        notes=cost_info.get("notes"),
        action="estimate",
    )
