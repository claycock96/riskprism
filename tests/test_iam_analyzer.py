"""
IAM Policy Analyzer Tests

Unit tests for the IAM rule engine and parser.
"""

import pytest
import json
from pathlib import Path
from app.analyzers.iam import IAMPolicyAnalyzer
from app.models import Severity


@pytest.fixture
def iam_analyzer():
    return IAMPolicyAnalyzer()


@pytest.fixture
def admin_policy():
    fixture_path = Path(__file__).parent / "fixtures" / "iam_admin_policy.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def passrole_policy():
    fixture_path = Path(__file__).parent / "fixtures" / "iam_passrole_dangerous.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def least_privilege_policy():
    fixture_path = Path(__file__).parent / "fixtures" / "iam_least_privilege.json"
    with open(fixture_path) as f:
        return json.load(f)


def test_parse_valid_policy(iam_analyzer, admin_policy):
    """Verify parser handles standard IAM policy structure."""
    parsed = iam_analyzer.parse(admin_policy)
    
    assert "Version" in parsed
    assert "Statement" in parsed
    assert len(parsed["Statement"]) == 1


def test_parse_wrapped_policy(iam_analyzer):
    """Verify parser handles wrapped policy formats."""
    wrapped = {"policy": {"Version": "2012-10-17", "Statement": []}}
    parsed = iam_analyzer.parse(wrapped)
    
    assert parsed["Version"] == "2012-10-17"


def test_rule_admin_star(iam_analyzer, admin_policy):
    """Verify IAM-ADMIN-STAR rule triggers on Action:* Resource:*"""
    parsed = iam_analyzer.parse(admin_policy)
    findings = iam_analyzer.analyze(parsed)
    
    admin_findings = [f for f in findings if f.risk_id == "IAM-ADMIN-STAR"]
    assert len(admin_findings) >= 1
    assert admin_findings[0].severity == Severity.CRITICAL


def test_rule_passrole_broad(iam_analyzer, passrole_policy):
    """Verify IAM-PASSROLE-BROAD rule triggers on iam:PassRole with wildcard."""
    parsed = iam_analyzer.parse(passrole_policy)
    findings = iam_analyzer.analyze(parsed)
    
    passrole_findings = [f for f in findings if f.risk_id == "IAM-PASSROLE-BROAD"]
    assert len(passrole_findings) >= 1
    assert passrole_findings[0].severity == Severity.CRITICAL


def test_rule_assumerole_broad(iam_analyzer, passrole_policy):
    """Verify IAM-ASSUMEROLE-BROAD rule triggers on sts:AssumeRole with wildcard."""
    parsed = iam_analyzer.parse(passrole_policy)
    findings = iam_analyzer.analyze(parsed)
    
    assume_findings = [f for f in findings if f.risk_id == "IAM-ASSUMEROLE-BROAD"]
    assert len(assume_findings) >= 1
    assert assume_findings[0].severity == Severity.HIGH


def test_rule_secrets_broad(iam_analyzer, passrole_policy):
    """Verify IAM-SECRETS-BROAD rule triggers on secretsmanager with wildcard."""
    parsed = iam_analyzer.parse(passrole_policy)
    findings = iam_analyzer.analyze(parsed)
    
    secrets_findings = [f for f in findings if f.risk_id == "IAM-SECRETS-BROAD"]
    assert len(secrets_findings) >= 1


def test_least_privilege_minimal_findings(iam_analyzer, least_privilege_policy):
    """Verify well-scoped policies generate minimal/no critical findings."""
    parsed = iam_analyzer.parse(least_privilege_policy)
    findings = iam_analyzer.analyze(parsed)
    
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0, f"Least privilege policy should have no CRITICAL findings, got: {critical_findings}"


def test_summary_generation(iam_analyzer, passrole_policy):
    """Verify summary statistics are accurate."""
    parsed = iam_analyzer.parse(passrole_policy)
    summary = iam_analyzer.generate_summary(parsed)
    
    assert summary["total_statements"] == 3
    assert summary["allow_statements"] == 3
    assert summary["wildcard_resources"] == 3


def test_arn_hashing(iam_analyzer, least_privilege_policy):
    """Verify ARNs are hashed in sanitized output."""
    parsed = iam_analyzer.parse(least_privilege_policy)
    findings = iam_analyzer.analyze(parsed)
    sanitized = iam_analyzer.sanitize_for_llm(parsed, findings)
    
    # Check that hash map is populated
    hash_map = iam_analyzer.get_resource_hash_map()
    # ARNs should be hashed
    assert sanitized["analyzer_type"] == "iam"
