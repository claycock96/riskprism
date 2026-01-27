from app.parser import TerraformPlanParser


def test_aggressive_sanitization():
    parser = TerraformPlanParser()

    # Mock some basic change data
    # 'ami' is in the allowlist, 'unknown_field' is NOT.
    # 'password' is specifically in the denylist (though everything not in allowlist is now redacted)

    before = {
        "ami": "ami-12345678",
        "instance_type": "t2.micro",
        "unknown_field": "sensitive-value",
        "db_password": "super-secret-password-123",  # pragma: allowlist secret
    }

    after = {
        "ami": "ami-87654321",
        "instance_type": "t2.small",
        "unknown_field": "new-sensitive-value",
        "db_password": "new-secret-password-456",  # pragma: allowlist secret
    }

    diffs = parser._extract_attribute_diffs(before, after)

    # Map diffs by path for easy check
    diff_map = {d.path: d for d in diffs}

    # Check allowlisted fields
    assert "ami" in diff_map
    assert diff_map["ami"].before == "ami-12345678"
    assert diff_map["ami"].after == "ami-87654321"

    # Check non-allowlisted fields (should be redacted)
    assert "unknown_field" in diff_map
    assert diff_map["unknown_field"].before == "[REDACTED]"
    assert diff_map["unknown_field"].after == "[REDACTED]"

    # Check denylisted/sensitive-looking fields
    assert "db_password" in diff_map
    assert diff_map["db_password"].before == "[REDACTED]"
    assert diff_map["db_password"].after == "[REDACTED]"


def test_secret_regex_redaction():
    parser = TerraformPlanParser()

    # Test that even allowlisted fields are redacted if they contain a secret
    before = {"description": "Standard description"}
    after = {
        "description": "Access Key: AKIA1234567890ABCDEF"  # pragma: allowlist secret
    }

    diffs = parser._extract_attribute_diffs(before, after)
    diff_map = {d.path: d for d in diffs}

    assert "description" in diff_map
    assert diff_map["description"].after == "[SECRET-DETECTED]"


def test_plan_hash_includes_values():
    parser = TerraformPlanParser()

    # Plan A
    skeleton_a = parser.extract_diff_skeleton(
        {
            "resource_changes": [
                {
                    "address": "aws_instance.web",
                    "type": "aws_instance",
                    "change": {
                        "actions": ["update"],
                        "before": {"instance_type": "t2.micro"},
                        "after": {"instance_type": "t2.small"},
                    },
                }
            ]
        }
    )
    hash_a = parser.calculate_plan_hash(skeleton_a)

    # Plan B (same resource and path, different value)
    skeleton_b = parser.extract_diff_skeleton(
        {
            "resource_changes": [
                {
                    "address": "aws_instance.web",
                    "type": "aws_instance",
                    "change": {
                        "actions": ["update"],
                        "before": {"instance_type": "t2.micro"},
                        "after": {"instance_type": "m5.large"},
                    },
                }
            ]
        }
    )
    hash_b = parser.calculate_plan_hash(skeleton_b)

    # They should be different because instance_type is in allowlist and its value changed
    assert hash_a != hash_b
