"""
IAM Policy Analyzer

Implements the BaseAnalyzer interface for AWS IAM Policy analysis.
Provides privacy-preserving analysis with ARN/Account ID hashing.
"""

import hashlib
import json
import logging
import re
from typing import Any

from app.models import RiskFinding, Severity

from .base import AnalyzerType, BaseAnalyzer

logger = logging.getLogger(__name__)


class IAMPolicyAnalyzer(BaseAnalyzer):
    """
    IAM Policy Analyzer.

    Analyzes AWS IAM policies for security risks using:
    - Deterministic rule engine (10+ rules)
    - ARN/Account ID hashing for privacy
    - Statement normalization for consistent analysis
    """

    analyzer_type = AnalyzerType.IAM

    # Patterns for sensitive data extraction and hashing
    ARN_PATTERN = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12})?:[a-zA-Z0-9/_-]+")
    ACCOUNT_ID_PATTERN = re.compile(r"\b\d{12}\b")

    # High-risk actions that require scrutiny
    HIGH_RISK_ACTIONS = {
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey",
        "s3:PutBucketPolicy",
        "s3:PutBucketAcl",
        "kms:PutKeyPolicy",
    }

    # Regex patterns for common secrets to catch them even in "safe" fields
    SECRET_PATTERNS = [
        re.compile(r"(?i)key-[a-zA-Z0-9]{20,}"),  # Generic key-like string
        re.compile(r"(?i)secret[_-]?key[:=]\s*[^\s]{10,}"),
        re.compile(r"(?i)password[:=]\s*[^\s]{8,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
        re.compile(r"[a-zA-Z0-9+/]{40}"),  # AWS Secret Key (approx)
        re.compile(r"sk_live_[0-9a-zA-Z]{24}"),  # Stripe Secret Key
    ]

    def __init__(self):
        self._arn_hash_map: dict[str, str] = {}  # hash -> original
        self._statements: list[dict[str, Any]] = []
        self._policy_document: dict[str, Any] = {}

    def parse(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """
        Parse and validate IAM policy JSON.

        Accepts:
        - Standard IAM policy document: {"Version": "...", "Statement": [...]}
        - Wrapped format: {"policy": {...}} or {"policy_document": {...}}
        """
        # Extract policy document from various wrapper formats
        policy = input_data
        if "policy" in input_data:
            policy = input_data["policy"]
        elif "policy_document" in input_data:
            policy = input_data["policy_document"]
        elif "Policy" in input_data:
            policy = input_data["Policy"]

        # Handle string-encoded policies
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in policy: {e}")

        # Validate structure
        if not isinstance(policy, dict):
            raise ValueError("Policy must be a dictionary")

        if "Statement" not in policy:
            raise ValueError("Policy must contain 'Statement' field")

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        # Normalize statements
        self._statements = [self._normalize_statement(stmt) for stmt in statements]
        self._policy_document = {"Version": policy.get("Version", "2012-10-17"), "Statement": self._statements}

        logger.info(f"Parsed IAM policy with {len(self._statements)} statements")
        return self._policy_document

    def _normalize_statement(self, stmt: dict[str, Any]) -> dict[str, Any]:
        """Normalize a single statement to consistent format."""
        normalized = {
            "Sid": stmt.get("Sid", ""),
            "Effect": stmt.get("Effect", "Allow"),
            "Action": self._ensure_list(stmt.get("Action", [])),
            "NotAction": self._ensure_list(stmt.get("NotAction", [])),
            "Resource": self._ensure_list(stmt.get("Resource", ["*"])),
            "NotResource": self._ensure_list(stmt.get("NotResource", [])),
            "Principal": stmt.get("Principal", "*"),
            "Condition": stmt.get("Condition", {}),
        }
        return normalized

    def _ensure_list(self, value: Any) -> list[str]:
        """Convert single value or list to list."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    def _hash_arn(self, arn: str) -> str:
        """Hash an ARN and store mapping."""
        hash_val = hashlib.sha256(arn.encode("utf-8")).hexdigest()[:12]
        hashed = f"arn_{hash_val}"
        self._arn_hash_map[hashed] = arn
        return hashed

    def _hash_sensitive_values(self, text: str) -> str:
        """Replace ARNs and account IDs with hashed versions."""
        # Hash ARNs
        for arn in self.ARN_PATTERN.findall(text):
            if arn:  # ARN found
                full_match = self.ARN_PATTERN.search(text)
                if full_match:
                    original_arn = full_match.group(0)
                    hashed = self._hash_arn(original_arn)
                    text = text.replace(original_arn, hashed, 1)

        # Hash account IDs
        for account_id in self.ACCOUNT_ID_PATTERN.findall(text):
            hash_val = hashlib.sha256(account_id.encode("utf-8")).hexdigest()[:8]
            hashed = f"acct_{hash_val}"
            self._arn_hash_map[hashed] = account_id
            text = text.replace(account_id, hashed)

        # Scan for secrets
        if len(text) >= 8:
            for pattern in self.SECRET_PATTERNS:
                if pattern.search(text):
                    logger.warning("SECRET DETECTED in IAM policy. Redacting.")
                    return "[SECRET-DETECTED]"

        return text

    def analyze(self, parsed_data: dict[str, Any], max_findings: int = 50) -> list[RiskFinding]:
        """Run IAM security rules."""
        findings: list[RiskFinding] = []

        has_deny = False
        for idx, stmt in enumerate(self._statements):
            if stmt.get("Effect") == "Deny":
                has_deny = True

            stmt_findings = self._analyze_statement(stmt, idx)
            findings.extend(stmt_findings)

            if len(findings) >= max_findings:
                break

        # Rule 32: Missing Guardrail Denies (Advisory)
        if not has_deny and any(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in findings):
            findings.append(
                RiskFinding(
                    risk_id="IAM-DENY-MISSING",
                    severity=Severity.LOW,
                    title="Missing Explicit Deny Guardrails",
                    description="Policy contains high-risk Allow statements but no explicit Deny statements to provide hard guardrails.",
                    resource_type="iam_policy",
                    resource_ref="global",
                    evidence={"has_deny": False},
                    recommendation="Consider adding explicit Deny statements for sensitive actions or regions to implement multiple layers of defense.",
                )
            )

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))

        logger.info(f"IAM analysis found {len(findings)} security issues")
        return findings[:max_findings]

    def _analyze_statement(self, stmt: dict[str, Any], stmt_idx: int) -> list[RiskFinding]:
        """Analyze a single statement for security issues."""
        findings: list[RiskFinding] = []

        effect = stmt.get("Effect", "Allow")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        conditions = stmt.get("Condition", {})
        principal = stmt.get("Principal", "*")

        # Only analyze Allow statements for most rules
        if effect != "Allow":
            return findings

        # Rule 1: Admin wildcard (Action: *, Resource: *)
        if "*" in actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-ADMIN-STAR",
                    severity=Severity.CRITICAL,
                    title="Full Administrator Access",
                    description='Statement grants Action: "*" with Resource: "*" - effectively granting full AWS administrator access.',
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": actions, "resources": resources},
                    recommendation="Replace wildcard with specific actions and resources following least privilege.",
                    suggested_fix='{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket-name/*"]}',
                )
            )

        # Rule 2: PassRole wildcard
        passrole_actions = [a for a in actions if a.lower() in ["iam:passrole", "iam:*", "*"]]
        if passrole_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-PASSROLE-BROAD",
                    severity=Severity.CRITICAL,
                    title="Broad iam:PassRole Permission",
                    description="PassRole on wildcard resources allows passing any role to any service - potential privilege escalation.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"passrole_actions": passrole_actions, "resources": resources},
                    recommendation="Restrict PassRole to specific role ARNs.",
                    suggested_fix='{"Resource": ["arn:aws:iam::ACCOUNT:role/specific-role"]}',
                )
            )

        # Rule 3: AssumeRole wildcard
        assume_actions = [a for a in actions if "assumerole" in a.lower() or a in ["sts:*", "*"]]
        if assume_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-ASSUMEROLE-BROAD",
                    severity=Severity.HIGH,
                    title="Broad sts:AssumeRole Permission",
                    description="AssumeRole on wildcard allows assuming any role in any account.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"assume_actions": assume_actions, "resources": resources},
                    recommendation="Restrict AssumeRole to specific role ARNs.",
                )
            )

        # Rule 4: S3 with public/wildcard principal
        s3_actions = [a for a in actions if a.startswith("s3:") or a in ["s3:*", "*"]]
        if s3_actions and principal == "*":
            findings.append(
                RiskFinding(
                    risk_id="IAM-S3-PUBLIC-ACCESS",
                    severity=Severity.HIGH,
                    title="S3 Actions with Public Principal",
                    description='S3 actions allowed for Principal: "*" - potentially public access.',
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"s3_actions": s3_actions, "principal": principal},
                    recommendation="Restrict Principal to specific AWS accounts or identities.",
                )
            )

        # Rule 5: KMS decrypt broad
        kms_actions = [a for a in actions if a.lower() in ["kms:decrypt", "kms:*", "*"]]
        if kms_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-KMS-DECRYPT-BROAD",
                    severity=Severity.HIGH,
                    title="Broad KMS Decrypt Permission",
                    description="kms:Decrypt on wildcard resources allows decrypting any KMS-encrypted data.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"kms_actions": kms_actions, "resources": resources},
                    recommendation="Restrict to specific KMS key ARNs.",
                )
            )

        # Rule 6: Secrets Manager broad
        secrets_actions = [a for a in actions if "secretsmanager" in a.lower() or a in ["secretsmanager:*", "*"]]
        if secrets_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-SECRETS-BROAD",
                    severity=Severity.HIGH,
                    title="Broad Secrets Manager Access",
                    description="Secrets Manager access on wildcard resources allows reading any secret.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"secrets_actions": secrets_actions, "resources": resources},
                    recommendation="Restrict to specific secret ARNs.",
                )
            )

        # Rule 7: Lambda invoke broad
        lambda_actions = [a for a in actions if a.lower() in ["lambda:invokefunction", "lambda:*", "*"]]
        if lambda_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-LAMBDA-INVOKE-BROAD",
                    severity=Severity.MEDIUM,
                    title="Broad Lambda Invoke Permission",
                    description="lambda:InvokeFunction on wildcard allows invoking any Lambda function.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"lambda_actions": lambda_actions, "resources": resources},
                    recommendation="Restrict to specific function ARNs.",
                )
            )

        # Rule 8: EC2 describe all (info)
        ec2_describe = [a for a in actions if a.lower().startswith("ec2:describe")]
        if len(ec2_describe) > 5:
            findings.append(
                RiskFinding(
                    risk_id="IAM-EC2-DESCRIBE-ALL",
                    severity=Severity.LOW,
                    title="Broad EC2 Describe Permissions",
                    description=f"Multiple EC2 Describe actions ({len(ec2_describe)}) may expose infrastructure details.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"ec2_describe_count": len(ec2_describe)},
                    recommendation="Review if all Describe actions are necessary.",
                )
            )

        # Rule 9: NotAction usage
        not_actions = stmt.get("NotAction", [])
        if not_actions:
            findings.append(
                RiskFinding(
                    risk_id="IAM-NOTACTION-USAGE",
                    severity=Severity.MEDIUM,
                    title="NotAction Pattern Detected",
                    description="NotAction grants all actions EXCEPT listed ones - can be overly permissive.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"not_actions": not_actions},
                    recommendation="Consider using explicit Action list instead.",
                )
            )

        # Rule 10: Missing conditions on sensitive actions
        sensitive_actions = [a for a in actions if a in self.HIGH_RISK_ACTIONS or a == "*"]
        if sensitive_actions and not conditions:
            findings.append(
                RiskFinding(
                    risk_id="IAM-CONDITION-MISSING",
                    severity=Severity.MEDIUM,
                    title="Sensitive Actions Without Conditions",
                    description="High-risk actions lack Condition constraints (MFA, source IP, etc.).",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"sensitive_actions": sensitive_actions[:5]},
                    recommendation="Add Condition constraints like aws:MultiFactorAuthPresent or aws:SourceIp.",
                )
            )

        # ========== Phase 7: Privilege Escalation & Trusts ==========

        # Rule 11: Policy Version Escalation
        version_actions = [
            a for a in actions if a.lower() in ["iam:createpolicyversion", "iam:setdefaultpolicyversion"]
        ]
        if len(set(version_actions)) >= 1 and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-POLICY-VERSION-PRIVESC",
                    severity=Severity.CRITICAL,
                    title="IAM Policy Version Escalation",
                    description="Allows creating or setting policy versions on all resources - direct path to full admin privileges.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": version_actions},
                    recommendation="Restrict these actions to specific policy ARNs or remove them entirely.",
                    suggested_fix='{"Action": ["iam:CreatePolicyVersion"], "Resource": ["arn:aws:iam::ACCOUNT:policy/TEAM-POLICY"]}',
                )
            )

        # Rule 12: Attach/Put Policy Escalation
        attach_actions = [
            a
            for a in actions
            if a.lower()
            in [
                "iam:attachuserpolicy",
                "iam:attachrolepolicy",
                "iam:attachgrouppolicy",
                "iam:putuserpolicy",
                "iam:putrolepolicy",
                "iam:putgrouppolicy",
            ]
        ]
        if attach_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-ATTACH-POLICY-PRIVESC",
                    severity=Severity.CRITICAL,
                    title="Policy Attachment Privilege Escalation",
                    description="Allows attaching or putting policies on arbitrary users/roles/groups - leads to full admin privileges.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": attach_actions},
                    recommendation="Restrict Resource to specific IAM entity ARNs.",
                )
            )

        # Rule 13: Update Trust Policy
        if any(a.lower() == "iam:updateassumerolepolicy" for a in actions) and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-UPDATE-TRUST-POLICY",
                    severity=Severity.CRITICAL,
                    title="Broad UpdateAssumeRolePolicy Permission",
                    description="Allows modifying trust policies of any role - can lead to account-wide lateral movement.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"action": "iam:UpdateAssumeRolePolicy"},
                    recommendation="Restrict to specific role ARNs.",
                )
            )

        # Rule 14: STS AssumeRole without ExternalID for 3rd parties
        if any("assumerole" in a.lower() for a in actions):
            # Check if Principal looks like a 3rd party (simplified check)
            principal_val = str(principal)
            if "AWS" in principal_val and ":" in principal_val and "ExternalId" not in str(conditions):
                findings.append(
                    RiskFinding(
                        risk_id="STS-ASSUMEROLE-NO-EXTERNALID",
                        severity=Severity.HIGH,
                        title="AssumeRole Without ExternalId for Third Party",
                        description="Trust policy allows third-party principal without ExternalID - vulnerable to Confused Deputy attack.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"principal": principal},
                        recommendation="Use sts:ExternalId condition for all third-party trust relationships.",
                    )
                )

        # Rule 15: Trusts Account Root
        if principal == "*" or (
            isinstance(principal, dict) and "AWS" in principal and ":root" in str(principal["AWS"])
        ):
            if not conditions:
                findings.append(
                    RiskFinding(
                        risk_id="STS-PRINCIPAL-ACCOUNT-ROOT",
                        severity=Severity.MEDIUM,
                        title="Trusts Account Root Without Conditions",
                        description="Granting access to account root allows any identity in that account to assume the role.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"principal": principal},
                        recommendation="Trust specific IAM principals or add Condition checks like aws:PrincipalArn.",
                    )
                )

        # Rule 16: Create Access Key (Missed from Phase 7)
        if any(a.lower() in ["iam:createaccesskey", "iam:updateaccesskey"] for a in actions) and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-CREATE-ACCESSKEY",
                    severity=Severity.HIGH,
                    title="Broad IAM Access Key Management",
                    description="Allows creating or updating access keys on all users - high risk for persistence and credential theft.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": [a for a in actions if "accesskey" in a.lower()]},
                    recommendation="Restrict to specific user ARNs or ${aws:username}.",
                )
            )

        # ========== Phase 8: Data Exfil & Misuse ==========

        # Rule 17: S3 Put Bucket Policy/ACL (Can make public)
        s3_mgmt_actions = [
            a for a in actions if a.lower() in ["s3:putbucketpolicy", "s3:putbucketacl", "s3:putinventoryconfiguration"]
        ]
        if s3_mgmt_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-S3-PUTBUCKETPOLICY",
                    severity=Severity.CRITICAL,
                    title="Broad S3 Management Permissions",
                    description="Allows modifying bucket policies or ACLs globally - can be used to make buckets public.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": s3_mgmt_actions},
                    recommendation="Restrict to specific bucket ARNs.",
                )
            )

        # Rule 18: Broad S3 GetObject
        if any(a.lower() == "s3:getobject" for a in actions) and any("*" in r for r in resources):
            # Check if resource is truly broad like arn:aws:s3:::*/*
            if any(r == "*" or "s3:::*" in r for r in resources):
                findings.append(
                    RiskFinding(
                        risk_id="IAM-S3-GETOBJECT-WILDCARD",
                        severity=Severity.HIGH,
                        title="Broad S3 Read Access",
                        description="Allows reading objects from all buckets or broad bucket patterns.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"action": "s3:GetObject", "resources": resources},
                        recommendation="Restrict to specific bucket/prefix ARNs.",
                    )
                )

        # Rule 19: KMS PutKeyPolicy
        if any(a.lower() == "kms:putkeypolicy" for a in actions) and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-KMS-PUTKEYPOLICY",
                    severity=Severity.CRITICAL,
                    title="Broad KMS Key Policy Management",
                    description="Allows modifying policies of any KMS key - leads to total crypto bypass and data access.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"action": "kms:PutKeyPolicy"},
                    recommendation="Restrict to specific key ARNs.",
                )
            )

        # Rule 20: Broad SSM/Secrets Read
        sensitive_read = [
            a
            for a in actions
            if a.lower()
            in ["ssm:getparameter", "ssm:getparameters", "ssm:getparametersby_path", "secretsmanager:getsecretvalue"]
        ]
        if sensitive_read and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-SENSITIVE-READ-BROAD",
                    severity=Severity.HIGH,
                    title="Broad Sensitive Data Read Access",
                    description="Allows reading any SSM parameter or Secret Manager secret.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": sensitive_read},
                    recommendation="Restrict to specific parameter or secret ARNs.",
                )
            )

        # Rule 21: Organizations Account Management
        org_actions = [
            a
            for a in actions
            if "organizations:" in a.lower() and a.lower() not in ["organizations:describe*", "organizations:list*"]
        ]
        if org_actions and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="ORG-ACCOUNT-MGMT",
                    severity=Severity.CRITICAL,
                    title="Dangerous Organization Management Permissions",
                    description="Allows sensitive organization operations like moving accounts or closing the account.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"actions": org_actions[:5]},
                    recommendation="Restrict organization actions to the master account and specific organizational unit ARNs.",
                )
            )

        # ========== Phase 9: Complex Escalation Chains ==========

        # Rule 22: EC2 + PassRole Chain
        if any(a.lower() == "ec2:runinstances" for a in actions) and any("passrole" in a.lower() for a in actions):
            if "*" in resources:
                findings.append(
                    RiskFinding(
                        risk_id="IAM-CHAIN-EC2-PRIVESC",
                        severity=Severity.CRITICAL,
                        title="EC2 + PassRole Privilege Escalation Chain",
                        description="Granting both ec2:RunInstances and iam:PassRole allows an identity to create a new instance with ANY role, achieving full privilege escalation.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"actions": ["ec2:RunInstances", "iam:PassRole"]},
                        recommendation="Restrict PassRole to specific roles and RunInstances to specific AMIs/Subnets.",
                    )
                )

        # Rule 23: Lambda + PassRole Chain
        lambda_write = [
            a
            for a in actions
            if a.lower() in ["lambda:createfunction", "lambda:updatefunctionconfiguration", "lambda:updatefunctioncode"]
        ]
        if lambda_write and any("passrole" in a.lower() for a in actions):
            if "*" in resources:
                findings.append(
                    RiskFinding(
                        risk_id="IAM-CHAIN-LAMBDA-PRIVESC",
                        severity=Severity.CRITICAL,
                        title="Lambda + PassRole Privilege Escalation Chain",
                        description="Allows creating or updating Lambda functions and passing arbitrary roles - full privilege escalation via code execution.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"actions": lambda_write + ["iam:PassRole"]},
                        recommendation="Restrict PassRole to specific roles.",
                    )
                )

        # Rule 24: EventBridge Injection
        if any(a.lower() == "events:puttargets" for a in actions) and any(
            a.lower() == "events:putrule" for a in actions
        ):
            if "*" in resources:
                findings.append(
                    RiskFinding(
                        risk_id="IAM-EVENTBRIDGE-INJECTION",
                        severity=Severity.HIGH,
                        title="EventBridge Target Injection",
                        description="Allows creating rules and injecting targets - can be used to trigger arbitrary compute (Lambda/SSM) with service-linked roles.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"actions": ["events:PutRule", "events:PutTargets"]},
                        recommendation="Restrict to specific EventBridge rule ARNs.",
                    )
                )

        # Rule 25: Lambda AddPermission Unscoped
        if any(a.lower() == "lambda:addpermission" for a in actions) and "*" in resources:
            findings.append(
                RiskFinding(
                    risk_id="IAM-LAMBDA-ADD-PERMISSION-BROAD",
                    severity=Severity.HIGH,
                    title="Broad Lambda AddPermission Permission",
                    description="Allows modifying any Lambda function policy globally - can be used to open functions to public/cross-account access.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"action": "lambda:AddPermission"},
                    recommendation="Restrict to specific function ARNs.",
                )
            )

        # Rule 26: ECS + PassRole Chain
        ecs_write = [a for a in actions if a.lower() in ["ecs:runtask", "ecs:createservice", "ecs:updateservice"]]
        if ecs_write and any("passrole" in a.lower() for a in actions):
            if "*" in resources:
                findings.append(
                    RiskFinding(
                        risk_id="IAM-CHAIN-ECS-PRIVESC",
                        severity=Severity.CRITICAL,
                        title="ECS + PassRole Privilege Escalation Chain",
                        description="Allows running ECS tasks and passing arbitrary roles - full privilege escalation via container execution.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"actions": ecs_write + ["iam:PassRole"]},
                        recommendation="Restrict PassRole to specific roles.",
                    )
                )

        # ========== Phase 10: Hygiene & Structure ==========

        # Rule 27: KMS CreateGrant Without Constraints
        if any(a.lower() == "kms:creategrant" for a in actions) and "*" in resources:
            if "kms:GrantIsForAWSResource" not in str(conditions):
                findings.append(
                    RiskFinding(
                        risk_id="IAM-KMS-CREATEGRANT",
                        severity=Severity.HIGH,
                        title="KMS CreateGrant Without Constraints",
                        description="Granting kms:CreateGrant without the kms:GrantIsForAWSResource condition allows an attacker to create arbitrary grants for any principal.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"action": "kms:CreateGrant"},
                        recommendation="Add kms:GrantIsForAWSResource condition to ensure grants are only usable by AWS services.",
                    )
                )

        # Rule 28: Decrypt Without Encryption Context
        if any(a.lower() == "kms:decrypt" for a in actions) and "*" in resources:
            if "kms:EncryptionContext" not in str(conditions):
                findings.append(
                    RiskFinding(
                        risk_id="IAM-KMS-DECRYPT-NO-CONTEXT",
                        severity=Severity.HIGH,
                        title="KMS Decrypt Without Encryption Context",
                        description="Allowing kms:Decrypt on all keys without a specific encryption context condition reduces the security of encrypted data.",
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"action": "kms:Decrypt"},
                        recommendation="Enforce encryption context conditions for sensitive data decryption.",
                    )
                )

        # Rule 29: Anonymous/Public Principal Variants
        principal_val = str(principal).replace(" ", "")
        if principal == "*" or '"AWS":"*"' in principal_val:
            if not conditions:
                findings.append(
                    RiskFinding(
                        risk_id="IAM-PRINCIPAL-ANON-OR-ALL",
                        severity=Severity.HIGH,
                        title="Anonymous or Public Principal Detected",
                        description='Granting access to "*" or {"AWS": "*"} without limiting conditions (IP/VPCe/OrgID) exposes resources to the public or all AWS accounts.',
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"principal": principal},
                        recommendation="Restrict Principal to specific identities or add strict Condition guardrails.",
                    )
                )

        # Rule 30: Allow + NotResource Pattern
        if stmt.get("NotResource") and effect == "Allow":
            findings.append(
                RiskFinding(
                    risk_id="IAM-ALLOW-NOTRESOURCE-WILDCARD",
                    severity=Severity.MEDIUM,
                    title="Allow + NotResource Pattern Detected",
                    description="Using Allow with NotResource is fragile and often leads to unintended broad permissions.",
                    resource_type="iam_policy_statement",
                    resource_ref=f"stmt_{stmt_idx}",
                    evidence={"not_resource": stmt.get("NotResource")},
                    recommendation="Use explicit Resource lists instead of NotResource whenever possible.",
                )
            )

        # Rule 31: Weak Condition Wildcards
        cond_str = str(conditions)
        if "StringLike" in cond_str and "*" in cond_str:
            if '"*"' in cond_str or '": "*' in cond_str:
                findings.append(
                    RiskFinding(
                        risk_id="IAM-CONDITION-STRINGLIKE-WILDCARD",
                        severity=Severity.MEDIUM,
                        title="Weak Wildcards in Policy Conditions",
                        description='Policy conditions use broad wildcards (e.g., StringLike: {"aws:PrincipalArn": "*"}), potentially bypassing intended restrictions.',
                        resource_type="iam_policy_statement",
                        resource_ref=f"stmt_{stmt_idx}",
                        evidence={"conditions": conditions},
                        recommendation="Use specific values or tightly scoped wildcards in conditions.",
                    )
                )

        return findings

    def sanitize_for_llm(self, parsed_data: dict[str, Any], findings: list[RiskFinding]) -> dict[str, Any]:
        """Create sanitized payload for LLM."""
        # Hash sensitive values in statements
        sanitized_statements = []
        for stmt in self._statements:
            sanitized_stmt = {
                "Effect": stmt["Effect"],
                "Action": stmt["Action"],
                "NotAction": stmt["NotAction"],
                "Resource": [self._hash_sensitive_values(r) for r in stmt["Resource"]],
                "NotResource": [self._hash_sensitive_values(r) for r in stmt["NotResource"]],
                "HasConditions": bool(stmt.get("Condition")),
            }
            sanitized_statements.append(sanitized_stmt)

        return {
            "analyzer_type": self.analyzer_type.value,
            "summary": self.generate_summary(parsed_data),
            "statements": sanitized_statements,
            "risk_findings": [f.model_dump() for f in findings],
        }

    def generate_summary(self, parsed_data: dict[str, Any]) -> dict[str, Any]:
        """Generate IAM policy summary."""
        allow_count = sum(1 for s in self._statements if s.get("Effect") == "Allow")
        deny_count = sum(1 for s in self._statements if s.get("Effect") == "Deny")
        wildcard_actions = sum(1 for s in self._statements if "*" in s.get("Action", []))
        wildcard_resources = sum(1 for s in self._statements if "*" in s.get("Resource", []))

        return {
            "total_statements": len(self._statements),
            "allow_statements": allow_count,
            "deny_statements": deny_count,
            "wildcard_actions": wildcard_actions,
            "wildcard_resources": wildcard_resources,
            "policy_version": parsed_data.get("Version", "2012-10-17"),
        }

    def get_resource_hash_map(self) -> dict[str, str]:
        """Get hash -> original ARN mapping."""
        return self._arn_hash_map

    def calculate_policy_hash(self) -> str:
        """
        Calculate a deterministic hash of the policy for caching.
        Uses normalized statement structure (actions, resources, effect).
        """
        # Create a stable representation of the policy
        policy_repr = []
        for stmt in self._statements:
            stmt_repr = {
                "Effect": stmt["Effect"],
                "Action": sorted(stmt["Action"]),
                "NotAction": sorted(stmt["NotAction"]),
                "Resource": sorted(stmt["Resource"]),
                "NotResource": sorted(stmt["NotResource"]),
                "HasConditions": bool(stmt.get("Condition")),
            }
            policy_repr.append(stmt_repr)

        # Sort statements for deterministic ordering
        policy_repr.sort(key=lambda x: json.dumps(x, sort_keys=True))

        # Calculate hash
        policy_str = json.dumps(policy_repr, sort_keys=True)
        return hashlib.sha256(policy_str.encode("utf-8")).hexdigest()
