"""
Unit tests for the cost estimation module.
"""

import pytest

from app.models import ResourceChange
from app.pricing import CostEstimate, CostEstimator, ResourceCost
from app.pricing.aws_pricing import (
    PRICING_LAST_UPDATED,
    PRICING_REGION,
    get_ebs_monthly_cost,
    get_ec2_hourly_cost,
    get_resource_pricing_info,
    is_free_resource,
)


class TestPricingDatabase:
    """Tests for the static pricing database."""

    def test_ec2_known_instance_type(self):
        """Known instance types should return high confidence."""
        hourly, confidence = get_ec2_hourly_cost("t3.micro")
        assert hourly > 0
        assert confidence == "high"

    def test_ec2_unknown_instance_type(self):
        """Unknown instance types should return lower confidence."""
        hourly, confidence = get_ec2_hourly_cost("x99.superlarge")
        assert hourly > 0  # Should return default
        assert confidence == "low"

    def test_ec2_no_instance_type(self):
        """Missing instance type should return default with medium confidence."""
        hourly, confidence = get_ec2_hourly_cost(None)
        assert hourly > 0
        assert confidence == "medium"

    def test_ebs_known_volume_type(self):
        """Known EBS types should calculate correctly."""
        monthly, confidence = get_ebs_monthly_cost("gp3", 100)
        assert monthly == pytest.approx(9.6, rel=0.1)  # $0.096 * 100GB
        assert confidence == "high"

    def test_ebs_default_values(self):
        """Default values should be applied when missing."""
        monthly, confidence = get_ebs_monthly_cost(None, None)
        assert monthly > 0
        assert confidence in ("high", "medium")

    def test_free_resources(self):
        """Free resources should be identified correctly."""
        assert is_free_resource("aws_iam_role") is True
        assert is_free_resource("aws_security_group") is True
        assert is_free_resource("aws_vpc") is True
        assert is_free_resource("aws_instance") is False

    def test_resource_pricing_ec2(self):
        """EC2 instances should be priced correctly."""
        info = get_resource_pricing_info("aws_instance", {"instance_type": "t3.medium"})
        assert info is not None
        assert info["monthly_cost"] > 0
        assert info["hourly_cost"] is not None
        assert info["confidence"] == "high"
        assert "t3.medium" in info["notes"]

    def test_resource_pricing_rds(self):
        """RDS instances should include storage cost."""
        info = get_resource_pricing_info("aws_db_instance", {"instance_class": "db.t3.micro", "allocated_storage": 50})
        assert info is not None
        assert info["monthly_cost"] > 0
        assert "50GB" in info["notes"]

    def test_resource_pricing_s3(self):
        """S3 buckets should return low confidence estimate."""
        info = get_resource_pricing_info("aws_s3_bucket", {})
        assert info is not None
        assert info["monthly_cost"] > 0
        assert info["confidence"] == "low"

    def test_resource_pricing_free_resource(self):
        """Free resources should return zero cost."""
        info = get_resource_pricing_info("aws_iam_role", {})
        assert info is not None
        assert info["monthly_cost"] == 0.0
        assert info["confidence"] == "high"
        assert info["pricing_unit"] == "free"

    def test_resource_pricing_unknown(self):
        """Unknown resources should return None."""
        info = get_resource_pricing_info("aws_fictional_service", {})
        assert info is None


class TestCostEstimator:
    """Tests for the CostEstimator class."""

    @pytest.fixture
    def estimator(self):
        return CostEstimator()

    @pytest.fixture
    def sample_diff_skeleton(self):
        """Create sample diff skeleton with various actions."""
        return [
            ResourceChange(
                resource_type="aws_instance",
                action="create",
                resource_ref="res_abc123",
                resource_address="aws_instance.web_server",
                changed_paths=["instance_type"],
                attribute_diffs=[],
            ),
            ResourceChange(
                resource_type="aws_security_group",
                action="create",
                resource_ref="res_def456",
                resource_address="aws_security_group.allow_http",
                changed_paths=["ingress"],
                attribute_diffs=[],
            ),
            ResourceChange(
                resource_type="aws_db_instance",
                action="create",
                resource_ref="res_ghi789",
                resource_address="aws_db_instance.main",
                changed_paths=["instance_class"],
                attribute_diffs=[],
            ),
        ]

    @pytest.fixture
    def sample_plan(self):
        """Create sample parsed plan with resource attributes."""
        return {
            "resource_changes": [
                {
                    "address": "aws_instance.web_server",
                    "type": "aws_instance",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {
                            "instance_type": "t3.medium",
                        },
                    },
                },
                {
                    "address": "aws_security_group.allow_http",
                    "type": "aws_security_group",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {
                            "name": "allow_http",
                        },
                    },
                },
                {
                    "address": "aws_db_instance.main",
                    "type": "aws_db_instance",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {
                            "instance_class": "db.t3.micro",
                            "allocated_storage": 20,
                        },
                    },
                },
            ]
        }

    def test_estimate_plan_cost_basic(self, estimator, sample_diff_skeleton, sample_plan):
        """Test basic cost estimation."""
        estimate = estimator.estimate_plan_cost(
            diff_skeleton=sample_diff_skeleton,
            parsed_plan=sample_plan,
            use_llm_fallback=False,
        )

        assert isinstance(estimate, CostEstimate)
        assert estimate.total_monthly_cost > 0
        assert estimate.currency == "USD"
        assert estimate.pricing_region == PRICING_REGION
        assert estimate.last_pricing_update == PRICING_LAST_UPDATED
        assert len(estimate.resource_costs) == 3

    def test_estimate_includes_free_resources(self, estimator, sample_diff_skeleton, sample_plan):
        """Free resources should be included with zero cost."""
        estimate = estimator.estimate_plan_cost(
            diff_skeleton=sample_diff_skeleton,
            parsed_plan=sample_plan,
            use_llm_fallback=False,
        )

        sg_cost = next((rc for rc in estimate.resource_costs if rc.resource_type == "aws_security_group"), None)
        assert sg_cost is not None
        assert sg_cost.monthly_cost == 0.0
        assert sg_cost.confidence == "high"

    def test_estimate_counts(self, estimator, sample_diff_skeleton, sample_plan):
        """Should track estimated vs unknown resource counts."""
        estimate = estimator.estimate_plan_cost(
            diff_skeleton=sample_diff_skeleton,
            parsed_plan=sample_plan,
            use_llm_fallback=False,
        )

        # All 3 resources should be estimated (EC2, SG, RDS)
        assert estimate.resources_estimated == 3
        assert estimate.resources_unknown == 0

    def test_estimate_delete_action(self, estimator):
        """Delete actions should reduce cost, not add it."""
        diff_skeleton = [
            ResourceChange(
                resource_type="aws_instance",
                action="delete",
                resource_ref="res_delete123",
                resource_address="aws_instance.old_server",
                changed_paths=[],
                attribute_diffs=[],
            ),
        ]
        plan = {
            "resource_changes": [
                {
                    "address": "aws_instance.old_server",
                    "type": "aws_instance",
                    "change": {
                        "actions": ["delete"],
                        "before": {"instance_type": "t3.medium"},
                        "after": None,
                    },
                },
            ]
        }

        estimate = estimator.estimate_plan_cost(
            diff_skeleton=diff_skeleton,
            parsed_plan=plan,
            use_llm_fallback=False,
        )

        # For deletes, total new cost should be 0, previous should be positive
        assert estimate.total_monthly_cost == 0.0
        assert estimate.previous_monthly_cost is not None
        assert estimate.previous_monthly_cost > 0

    def test_estimate_update_action(self, estimator):
        """Update actions should calculate percent change."""
        diff_skeleton = [
            ResourceChange(
                resource_type="aws_instance",
                action="update",
                resource_ref="res_update123",
                resource_address="aws_instance.resized",
                changed_paths=["instance_type"],
                attribute_diffs=[],
            ),
        ]
        plan = {
            "resource_changes": [
                {
                    "address": "aws_instance.resized",
                    "type": "aws_instance",
                    "change": {
                        "actions": ["update"],
                        "before": {"instance_type": "t3.micro"},
                        "after": {"instance_type": "t3.xlarge"},
                    },
                },
            ]
        }

        estimate = estimator.estimate_plan_cost(
            diff_skeleton=diff_skeleton,
            parsed_plan=plan,
            use_llm_fallback=False,
        )

        # Upgrading from t3.micro to t3.xlarge should increase cost
        assert estimate.total_monthly_cost > 0
        assert estimate.previous_monthly_cost is not None
        assert estimate.previous_monthly_cost > 0
        assert estimate.percent_change is not None
        assert estimate.percent_change > 0  # Should be a positive change
        assert estimate.net_change is not None
        assert estimate.net_change > 0

    def test_resource_cost_model(self):
        """ResourceCost model should serialize correctly."""
        cost = ResourceCost(
            resource_ref="res_test123",
            resource_type="aws_instance",
            resource_address="aws_instance.test",
            monthly_cost=36.50,
            hourly_cost=0.05,
            confidence="high",
            pricing_unit="per hour",
            notes="t3.medium",
            action="create",
        )

        data = cost.model_dump()
        assert data["resource_type"] == "aws_instance"
        assert data["monthly_cost"] == 36.50
        assert data["confidence"] == "high"


class TestPricingMetadata:
    """Tests for pricing metadata."""

    def test_pricing_region_is_govcloud(self):
        """Pricing should be for us-gov-west-1."""
        assert PRICING_REGION == "us-gov-west-1"

    def test_pricing_last_updated_format(self):
        """Last updated should be ISO date format."""
        # Should be in YYYY-MM-DD format
        assert len(PRICING_LAST_UPDATED) == 10
        assert PRICING_LAST_UPDATED.count("-") == 2
