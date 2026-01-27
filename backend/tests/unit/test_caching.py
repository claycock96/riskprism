import pytest

from app.models import ResourceChange
from app.parser import TerraformPlanParser


@pytest.fixture
def parser():
    return TerraformPlanParser()


def test_fingerprint_deterministic(parser):
    """Verify that identical plans produce identical hashes regardless of input order."""

    # Plan A
    skeleton_a = [
        ResourceChange(
            resource_type="aws_s3_bucket",
            action="create",
            changed_paths=["bucket"],
            attribute_diffs=[],
            resource_ref="hash_1",
            resource_address="addr1",
        ),
        ResourceChange(
            resource_type="aws_iam_user",
            action="update",
            changed_paths=["name"],
            attribute_diffs=[],
            resource_ref="hash_2",
            resource_address="addr2",
        ),
    ]

    # Plan B (Same content, different list order)
    skeleton_b = [
        ResourceChange(
            resource_type="aws_iam_user",
            action="update",
            changed_paths=["name"],
            attribute_diffs=[],
            resource_ref="hash_2",
            resource_address="addr2",
        ),
        ResourceChange(
            resource_type="aws_s3_bucket",
            action="create",
            changed_paths=["bucket"],
            attribute_diffs=[],
            resource_ref="hash_1",
            resource_address="addr1",
        ),
    ]

    hash_a = parser.calculate_plan_hash(skeleton_a)
    hash_b = parser.calculate_plan_hash(skeleton_b)

    assert len(hash_a) == 64  # SHA-256 length
    assert hash_a == hash_b  # Must match exactly for caching to work


def test_fingerprint_sensitive_to_structure(parser):
    """Verify that changing an action or resource type changes the hash."""

    skeleton_a = [
        ResourceChange(
            resource_type="aws_s3_bucket",
            action="create",
            changed_paths=["bucket"],
            attribute_diffs=[],
            resource_ref="hash_1",
            resource_address="addr1",
        )
    ]

    # Change action from create to update
    skeleton_b = [
        ResourceChange(
            resource_type="aws_s3_bucket",
            action="update",
            changed_paths=["bucket"],
            attribute_diffs=[],
            resource_ref="hash_1",
            resource_address="addr1",
        )
    ]

    assert parser.calculate_plan_hash(skeleton_a) != parser.calculate_plan_hash(skeleton_b)
