import pytest
import json
from app.risk_engine import RiskEngine
from app.models import Severity

@pytest.fixture
def risk_engine():
    return RiskEngine()

def test_rule_iam_passrole_wildcard(risk_engine):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*"
            }
        ]
    }
    change = {
        "address": "aws_iam_policy.dangerous",
        "type": "aws_iam_policy",
        "change": {
            "after": {
                "policy": json.dumps(policy)
            }
        }
    }
    findings = risk_engine.analyze({"resource_changes": [change]}, [])
    
    assert any(f.risk_id == "IAM-PASSROLE-BROAD" for f in findings)
    finding = next(f for f in findings if f.risk_id == "IAM-PASSROLE-BROAD")
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["resource_wildcard"] is True

def test_rule_sts_assumerole_wildcard(risk_engine):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }
        ]
    }
    change = {
        "address": "aws_iam_policy.broad_assume",
        "type": "aws_iam_policy",
        "change": {
            "after": {
                "policy": json.dumps(policy)
            }
        }
    }
    findings = risk_engine.analyze({"resource_changes": [change]}, [])
    
    assert any(f.risk_id == "STS-ASSUMEROLE-WILDCARD" for f in findings)
    finding = next(f for f in findings if f.risk_id == "STS-ASSUMEROLE-WILDCARD")
    assert finding.severity == Severity.HIGH
    assert finding.evidence["resource_wildcard"] is True

def test_rule_nacl_allow_all(risk_engine):
    change = {
        "address": "aws_network_acl_rule.allow_all",
        "type": "aws_network_acl_rule",
        "change": {
            "after": {
                "rule_action": "allow",
                "protocol": "-1",
                "cidr_block": "0.0.0.0/0"
            }
        }
    }
    findings = risk_engine.analyze({"resource_changes": [change]}, [])
    
    assert any(f.risk_id == "NACL-ALLOW-ALL" for f in findings)
    finding = next(f for f in findings if f.risk_id == "NACL-ALLOW-ALL")
    assert finding.severity == Severity.HIGH
    assert finding.evidence["protocol"] == "all"

def test_rule_lb_internet_facing(risk_engine):
    change = {
        "address": "aws_lb.public",
        "type": "aws_lb",
        "change": {
            "after": {
                "internal": False
            }
        }
    }
    findings = risk_engine.analyze({"resource_changes": [change]}, [])
    
    assert any(f.risk_id == "LB-INTERNET-FACING" for f in findings)
    finding = next(f for f in findings if f.risk_id == "LB-INTERNET-FACING")
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["internal"] is False

def test_rule_ebs_encryption_off(risk_engine):
    change = {
        "address": "aws_ebs_volume.unencrypted",
        "type": "aws_ebs_volume",
        "change": {
            "after": {
                "encrypted": False
            }
        }
    }
    findings = risk_engine.analyze({"resource_changes": [change]}, [])
    
    assert any(f.risk_id == "EBS-ENCRYPTION-OFF" for f in findings)
    finding = next(f for f in findings if f.risk_id == "EBS-ENCRYPTION-OFF")
    assert finding.severity == Severity.HIGH
    assert finding.evidence["encrypted"] is False
