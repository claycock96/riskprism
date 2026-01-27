import hashlib
import logging
from typing import Any

from app.models import ResourceChange, RiskFinding, Severity

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Deterministic risk detection engine for Terraform plans.

    Implements security rules that analyze parsed plan data and
    generate risk findings with safe evidence tokens.

    Key principles:
    - Deterministic: same plan always produces same findings
    - Safe evidence: no sensitive values in outputs
    - Explainable: clear evidence and recommendations
    """

    def __init__(self):
        self.rules = [
            self._rule_sg_open_ingress,
            self._rule_s3_public_acl_or_policy,
            self._rule_s3_pab_removed,
            self._rule_s3_encryption_removed,
            self._rule_rds_publicly_accessible,
            self._rule_rds_encryption_off,
            self._rule_iam_admin_wildcard,
            self._rule_iam_managed_policy_attachment,
            self._rule_cloudtrail_disabled,
            self._rule_iam_passrole_wildcard,
            self._rule_sts_assumerole_wildcard,
            self._rule_nacl_allow_all,
            self._rule_lb_internet_facing,
            self._rule_ebs_encryption_off,
            # Phase 1: Network & Perimeter
            self._rule_sg_open_egress_all,
            self._rule_sg_ingress_wide_cidr,
            self._rule_nacl_ephemeral_open,
            self._rule_route_igw_default,
            self._rule_vpc_peering_open,
            self._rule_tgw_attach_unrestricted,
            # Phase 2: Logging & Monitoring
            self._rule_vpc_flowlogs_off,
            self._rule_guardduty_off,
            self._rule_securityhub_off,
            self._rule_config_off,
            self._rule_loggroup_retention_infinite,
            self._rule_cloudtrail_log_validation_off,
            self._rule_cloudtrail_no_kms,
            # Phase 3: Data Protection & Encryption
            self._rule_kms_key_rotation_off,
            self._rule_kms_policy_open_account,
            self._rule_ecr_scan_on_push_off,
            self._rule_ecr_public_repo,
            self._rule_s3_versioning_off,
            self._rule_ddb_pitr_off,
            self._rule_sqs_sse_off,
            self._rule_sns_sse_off,
            # Phase 4: Destructive & Safety Controls
            self._rule_rds_deletion_protection_off,
            self._rule_rds_backup_retention_low,
            self._rule_rds_public_snapshots,
            self._rule_ebs_snapshot_public,
            self._rule_s3_force_destroy_true,
            self._rule_kms_schedule_delete,
            # Phase 5: Compute & App Exposure
            self._rule_ec2_imdsv1_allowed,
            self._rule_ec2_public_ip_assigned,
            self._rule_asg_min_size_zero,
            self._rule_lambda_url_auth_none,
            self._rule_apigw_open_auth,
            self._rule_alb_accesslogs_off,
        ]

    def analyze(
        self, plan_json: dict[str, Any], diff_skeleton: list[ResourceChange], max_findings: int = 50
    ) -> list[RiskFinding]:
        """
        Run all risk rules against the plan.

        Args:
            plan_json: Parsed Terraform plan JSON
            diff_skeleton: Minimal resource change representation
            max_findings: Maximum findings to return

        Returns:
            List of RiskFinding objects
        """
        findings = []

        resource_changes = plan_json.get("resource_changes", [])

        for change in resource_changes:
            # Skip no-op changes
            actions = change.get("change", {}).get("actions", [])
            if actions == ["no-op"]:
                continue

            # Run all rules against this resource change
            for rule in self.rules:
                try:
                    finding = rule(change, plan_json)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Rule execution failed: {e}")

        # Sort by severity (critical first) and limit results
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        findings.sort(key=lambda f: severity_order[f.severity])

        logger.info(f"Risk analysis complete: {len(findings)} findings")
        return findings[:max_findings]

    def _hash_resource_ref(self, address: str) -> str:
        """Generate stable hash for resource address"""
        hash_obj = hashlib.sha256(address.encode("utf-8"))
        return f"res_{hash_obj.hexdigest()[:10]}"

    # ========== Risk Rules ==========

    def _rule_sg_open_ingress(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        SG-OPEN-INGRESS: Security group allows public ingress

        Triggers on:
        - aws_security_group with ingress rules containing 0.0.0.0/0 or ::/0
        - aws_security_group_rule with public CIDR
        """
        resource_type = change.get("type", "")

        if resource_type not in ["aws_security_group", "aws_security_group_rule"]:
            return None

        change_data = change.get("change", {})
        after = change_data.get("after", {})

        if not after:
            return None

        # Check ingress rules
        ingress_rules = after.get("ingress", []) if resource_type == "aws_security_group" else []

        # For aws_security_group_rule, check the rule itself
        if resource_type == "aws_security_group_rule":
            rule_type = after.get("type")
            if rule_type == "ingress":
                ingress_rules = [after]

        public_cidrs = []
        exposed_ports = []

        for rule in ingress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks", [])

            # Check for public CIDRs
            if "0.0.0.0/0" in cidr_blocks or "::/0" in ipv6_cidr_blocks:
                public_cidrs.append("public")

                # Extract ports
                from_port = rule.get("from_port")
                to_port = rule.get("to_port")

                if from_port is not None:
                    exposed_ports.append(from_port)

        if not public_cidrs:
            return None

        # Determine severity based on ports
        critical_ports = {22, 3389, 5432, 3306, 1433, 27017}
        severity = Severity.CRITICAL if any(p in critical_ports for p in exposed_ports) else Severity.HIGH

        return RiskFinding(
            risk_id="SG-OPEN-INGRESS",
            title="Security group allows public internet ingress",
            severity=severity,
            resource_type=resource_type,
            resource_ref=self._hash_resource_ref(change.get("address", "")),
            evidence={
                "public_cidr": True,
                "exposed_ports": exposed_ports if exposed_ports else ["unspecified"],
                "critical_port_exposed": any(p in critical_ports for p in exposed_ports),
            },
            recommendation="Restrict CIDR blocks to known IP ranges. For SSH/RDP, use AWS Systems Manager Session Manager or a bastion host. For databases, ensure they are in private subnets with security groups allowing only application tier access.",
            suggested_fix='ingress {\n  from_port   = 443\n  to_port     = 443\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"] # Restricted range\n}',
            changed_paths=None,
        )

    def _rule_s3_public_acl_or_policy(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        S3-PUBLIC-ACL-OR-POLICY: S3 bucket has public access via policy or ACL
        """
        resource_type = change.get("type", "")

        if resource_type not in ["aws_s3_bucket_policy", "aws_s3_bucket_acl", "aws_s3_bucket"]:
            return None

        change_data = change.get("change", {})
        after = change_data.get("after", {})

        if not after:
            return None

        # Check bucket policy for Principal: "*"
        if resource_type == "aws_s3_bucket_policy":
            policy = after.get("policy", "")
            if isinstance(policy, str) and '"Principal":"*"' in policy.replace(" ", ""):
                return RiskFinding(
                    risk_id="S3-PUBLIC-ACL-OR-POLICY",
                    title="S3 bucket policy allows public access",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"principal_star": True, "public_read_risk": True},
                    recommendation="Remove Principal: '*' from bucket policy or add strict conditions. Enable S3 Block Public Access settings. Use CloudFront with OAC for public content distribution.",
                    suggested_fix='statement {\n  principals {\n    type        = "AWS"\n    identifiers = ["arn:aws:iam::123456789012:role/MyRole"]\n  }\n  actions = ["s3:GetObject"]\n}',
                    changed_paths=None,
                )

        # Check bucket ACL
        if resource_type in ["aws_s3_bucket_acl", "aws_s3_bucket"]:
            acl = after.get("acl", "")
            if acl in ["public-read", "public-read-write"]:
                return RiskFinding(
                    risk_id="S3-PUBLIC-ACL-OR-POLICY",
                    title="S3 bucket ACL allows public access",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"public_acl": acl, "public_write": acl == "public-read-write"},
                    recommendation="Change ACL to 'private'. Enable S3 Block Public Access. Use bucket policies with specific principals for controlled sharing.",
                    suggested_fix='acl = "private"',
                    changed_paths=None,
                )

        return None

    def _rule_s3_pab_removed(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        S3-PAB-REMOVED: S3 Public Access Block settings disabled or removed
        """
        resource_type = change.get("type", "")

        if resource_type != "aws_s3_bucket_public_access_block":
            return None

        change_data = change.get("change", {})
        actions = change_data.get("actions", [])
        before = change_data.get("before", {})
        after = change_data.get("after", {})

        # Check for deletion
        if "delete" in actions:
            return RiskFinding(
                risk_id="S3-PAB-REMOVED",
                title="S3 Public Access Block removed",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"pab_removed": True},
                recommendation="Keep S3 Block Public Access enabled unless explicitly required for public content. Document exceptions.",
                suggested_fix='resource "aws_s3_bucket_public_access_block" "example" {\n  bucket = aws_s3_bucket.example.id\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
                changed_paths=None,
            )

        # Check for disabling settings
        if after:
            disabled_settings = []
            for setting in [
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            ]:
                if after.get(setting) is False:
                    disabled_settings.append(setting)

            if disabled_settings:
                return RiskFinding(
                    risk_id="S3-PAB-REMOVED",
                    title="S3 Public Access Block settings disabled",
                    severity=Severity.HIGH,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"pab_disabled": True, "disabled_settings": disabled_settings},
                    recommendation="Enable all Block Public Access settings unless public access is explicitly required and approved.",
                    suggested_fix="block_public_acls       = true\nblock_public_policy     = true\nignore_public_acls      = true\nrestrict_public_buckets = true",
                    changed_paths=None,
                )

        return None

    def _rule_s3_encryption_removed(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        S3-ENCRYPTION-REMOVED: S3 bucket encryption disabled
        """
        resource_type = change.get("type", "")

        if resource_type != "aws_s3_bucket_server_side_encryption_configuration":
            return None

        change_data = change.get("change", {})
        actions = change_data.get("actions", [])

        if "delete" in actions:
            return RiskFinding(
                risk_id="S3-ENCRYPTION-REMOVED",
                title="S3 bucket encryption removed",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"sse_removed": True},
                recommendation="Enable server-side encryption. Use SSE-KMS for sensitive data. Consider compliance requirements.",
                suggested_fix='resource "aws_s3_bucket_server_side_encryption_configuration" "example" {\n  bucket = aws_s3_bucket.example.id\n\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}',
                changed_paths=None,
            )

        return None

    def _rule_rds_publicly_accessible(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        RDS-PUBLICLY-ACCESSIBLE: RDS instance exposed to public internet
        """
        resource_type = change.get("type", "")

        if resource_type != "aws_db_instance":
            return None

        change_data = change.get("change", {})
        after = change_data.get("after", {})

        if after and after.get("publicly_accessible") is True:
            return RiskFinding(
                risk_id="RDS-PUBLICLY-ACCESSIBLE",
                title="RDS instance is publicly accessible",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"publicly_accessible": True},
                recommendation="Set publicly_accessible to false. Place RDS in private subnets. Use VPC security groups to restrict access to application tier only.",
                suggested_fix="publicly_accessible = false",
                changed_paths=None,
            )

        return None

    def _rule_rds_encryption_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        RDS-ENCRYPTION-OFF: RDS instance encryption disabled
        """
        resource_type = change.get("type", "")

        if resource_type != "aws_db_instance":
            return None

        change_data = change.get("change", {})
        after = change_data.get("after", {})

        if after and after.get("storage_encrypted") is False:
            return RiskFinding(
                risk_id="RDS-ENCRYPTION-OFF",
                title="RDS instance storage encryption disabled",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"encryption_disabled": True},
                recommendation="Enable storage_encrypted. Note: existing instances require snapshot, restore to new encrypted instance. Plan for maintenance window.",
                suggested_fix="storage_encrypted = true",
                changed_paths=None,
            )

        return None

    def _rule_iam_admin_wildcard(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        IAM-ADMIN-WILDCARD: IAM policy uses wildcard actions or resources
        """
        resource_type = change.get("type", "")

        if resource_type not in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]:
            return None

        change_data = change.get("change", {})
        after = change_data.get("after", {})

        if not after:
            return None

        policy = after.get("policy", "")

        if not isinstance(policy, str):
            return None

        # Simple heuristic: check for Action: "*" or broad service wildcards
        dangerous_patterns = ['"Action":"*"', '"Action":["*"]', '"iam:*"', '"Resource":"*"']

        if any(pattern.replace(" ", "") in policy.replace(" ", "") for pattern in dangerous_patterns):
            return RiskFinding(
                risk_id="IAM-ADMIN-WILDCARD",
                title="IAM policy contains wildcard permissions",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"action_wildcard": True, "admin_risk": True},
                recommendation="Scope IAM actions and resources to least privilege. Avoid Action: '*' and Resource: '*'. Use separate break-glass admin roles with MFA and monitoring.",
                suggested_fix='statement {\n  actions   = ["ec2:Describe*", "s3:ListBucket"]\n  resources = ["*"]\n  # Prefer specific resource ARNs where possible\n}',
                changed_paths=None,
            )

        return None

    def _rule_iam_managed_policy_attachment(
        self, change: dict[str, Any], plan_json: dict[str, Any]
    ) -> RiskFinding | None:
        """
        IAM-MANAGED-POLICY: Dangerous AWS managed policy attachment
        """
        resource_type = change.get("type", "")

        # Check for policy attachment resources
        if resource_type not in [
            "aws_iam_role_policy_attachment",
            "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment",
        ]:
            return None

        change_data = change.get("change", {})
        after = change_data.get("after", {})

        if not after:
            return None

        policy_arn = after.get("policy_arn", "")

        if not isinstance(policy_arn, str):
            return None

        # List of dangerous AWS managed policies
        dangerous_policies = {
            "AdministratorAccess": "Grants full access to all AWS services and resources",
            "PowerUserAccess": "Grants full access except IAM and Organizations management",
            "IAMFullAccess": "Grants full access to IAM, enabling privilege escalation",
            "SecurityAudit": "Grants read access to security-related AWS resources",
            "SystemAdministrator": "Grants full access to AWS services except billing",
        }

        # Check if the policy ARN matches any dangerous policies
        for policy_name, description in dangerous_policies.items():
            if policy_name in policy_arn:
                # Determine severity based on the policy
                if policy_name in ["AdministratorAccess", "IAMFullAccess"]:
                    severity = Severity.CRITICAL
                elif policy_name == "PowerUserAccess":
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                return RiskFinding(
                    risk_id="IAM-MANAGED-POLICY",
                    title=f"Dangerous AWS managed policy attached: {policy_name}",
                    severity=severity,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={
                        "policy_arn": policy_arn,
                        "policy_name": policy_name,
                        "description": description,
                        "action": change_data.get("actions", []),
                    },
                    recommendation=f"Review the need for {policy_name}. This policy grants excessive permissions. Consider using a custom policy with least-privilege permissions or a more restrictive AWS managed policy. For break-glass admin access, use a separate role with MFA and strict approval workflows.",
                    suggested_fix='# Replace with a more restrictive managed policy or a custom policy\npolicy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"',
                    changed_paths=None,
                )

        return None

    def _rule_cloudtrail_disabled(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        CT-LOGGING-DISABLED: CloudTrail logging disabled or removed
        """
        resource_type = change.get("type", "")

        if resource_type != "aws_cloudtrail":
            return None

        change_data = change.get("change", {})
        actions = change_data.get("actions", [])
        after = change_data.get("after", {})

        # Check for deletion
        if "delete" in actions:
            return RiskFinding(
                risk_id="CT-LOGGING-DISABLED",
                title="CloudTrail logging removed",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"cloudtrail_removed": True},
                recommendation="Maintain CloudTrail logging for audit and compliance. Use organization trails for multi-account coverage.",
                suggested_fix="# Do not delete aws_cloudtrail resources in production",
                changed_paths=None,
            )

        # Check if logging is disabled
        if after and after.get("enable_logging") is False:
            return RiskFinding(
                risk_id="CT-LOGGING-DISABLED",
                title="CloudTrail logging disabled",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"cloudtrail_disabled": True},
                recommendation="Enable CloudTrail logging. Ensure logs are protected with encryption and access controls.",
                suggested_fix="enable_logging = true",
                changed_paths=None,
            )

        return None

    def _rule_iam_passrole_wildcard(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        IAM-PASSROLE-BROAD: iam:PassRole allowed on wildcard resource
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after or not isinstance(after.get("policy"), str):
            return None

        policy = after.get("policy", "").replace(" ", "")
        if '"Action":"iam:PassRole"' in policy or '"Action":["iam:PassRole"]' in policy:
            if '"Resource":"*"' in policy or '"Resource":["*"]' in policy:
                return RiskFinding(
                    risk_id="IAM-PASSROLE-BROAD",
                    title="IAM policy allows iam:PassRole on all resources",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"action": "iam:PassRole", "resource_wildcard": True},
                    recommendation="Restrict iam:PassRole to specific role ARNs. Wildcard PassRole allows an attacker to pass ANY role to a service, leading to full privilege escalation.",
                    suggested_fix='statement {\n  actions   = ["iam:PassRole"]\n  resources = ["arn:aws:iam::123456789012:role/SpecificServiceRole"]\n}',
                    changed_paths=None,
                )
        return None

    def _rule_sts_assumerole_wildcard(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        STS-ASSUMEROLE-WILDCARD: sts:AssumeRole allowed on wildcard resource
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after or not isinstance(after.get("policy"), str):
            return None

        policy = after.get("policy", "").replace(" ", "")
        if '"Action":"sts:AssumeRole"' in policy or '"Action":["sts:AssumeRole"]' in policy:
            if '"Resource":"*"' in policy or '"Resource":["*"]' in policy:
                return RiskFinding(
                    risk_id="STS-ASSUMEROLE-WILDCARD",
                    title="IAM policy allows sts:AssumeRole on all resources",
                    severity=Severity.HIGH,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"action": "sts:AssumeRole", "resource_wildcard": True},
                    recommendation="Restrict sts:AssumeRole to specific role ARNs. Broad AssumeRole permissions increase the blast radius of compromised credentials.",
                    suggested_fix='statement {\n  actions   = ["sts:AssumeRole"]\n  resources = ["arn:aws:iam::123456789012:role/SpecificCrossAccountRole"]\n}',
                    changed_paths=None,
                )
        return None

    def _rule_nacl_allow_all(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        NACL-ALLOW-ALL: Network ACL allows all traffic from any source
        """
        resource_type = change.get("type", "")
        if resource_type != "aws_network_acl_rule":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        # rule_action="allow", protocol="-1" (all), cidr_block="0.0.0.0/0"
        if (
            after.get("rule_action") == "allow"
            and str(after.get("protocol")) == "-1"
            and (after.get("cidr_block") == "0.0.0.0/0" or after.get("ipv6_cidr_block") == "::/0")
        ):
            return RiskFinding(
                risk_id="NACL-ALLOW-ALL",
                title="Network ACL allows all traffic from any source",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={
                    "rule_action": "allow",
                    "protocol": "all",
                    "cidr_block": after.get("cidr_block") or after.get("ipv6_cidr_block"),
                },
                recommendation="Restrict Network ACL rules to specific protocols and CIDR blocks. Prefer Security Groups for stateful traffic control.",
                suggested_fix='rule_action = "allow"\nprotocol    = "tcp"\nfrom_port   = 443\nto_port     = 443\ncidr_block  = "10.0.0.0/16"',
                changed_paths=None,
            )
        return None

    def _rule_lb_internet_facing(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        LB-INTERNET-FACING: Load balancer is internet-facing
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_lb", "aws_alb", "aws_elb"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        # aws_lb/aws_alb uses 'internal', aws_elb uses 'internal'
        is_internal = after.get("internal")

        # If internal is false (or explicitly set to false), it's internet-facing
        if is_internal is False:
            return RiskFinding(
                risk_id="LB-INTERNET-FACING",
                title="Load balancer is internet-facing",
                severity=Severity.MEDIUM,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"internal": False},
                recommendation="Ensure the load balancer is intended to be public. Use WAF and restrictive Security Groups to protect public endpoints.",
                suggested_fix="internal = true",
                changed_paths=None,
            )
        return None

    def _rule_ebs_encryption_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        EBS-ENCRYPTION-OFF: EBS volume encryption is disabled
        """
        resource_type = change.get("type", "")
        if resource_type != "aws_ebs_volume":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("encrypted") is False:
            return RiskFinding(
                risk_id="EBS-ENCRYPTION-OFF",
                title="EBS volume encryption is disabled",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"encrypted": False},
                recommendation="Enable EBS encryption to protect data at rest. You can enable account-level default encryption in the AWS region.",
                suggested_fix="encrypted = true",
                changed_paths=None,
            )
        return None

    # ========== Phase 1: Network & Perimeter Rules ==========

    def _rule_sg_open_egress_all(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        SG-OPEN-EGRESS-ALL: Unrestricted Egress
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_security_group", "aws_security_group_rule"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        egress_rules = after.get("egress", []) if resource_type == "aws_security_group" else []
        if resource_type == "aws_security_group_rule" and after.get("type") == "egress":
            egress_rules = [after]

        for rule in egress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks", [])
            protocol = str(rule.get("protocol", ""))
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            if "0.0.0.0/0" in cidr_blocks or "::/0" in ipv6_cidr_blocks:
                # Check for all traffic or full port range
                if protocol == "-1" or (from_port == 0 and to_port == 65535):
                    return RiskFinding(
                        risk_id="SG-OPEN-EGRESS-ALL",
                        title="Unrestricted Egress Allowed",
                        severity=Severity.HIGH,
                        resource_type=resource_type,
                        resource_ref=self._hash_resource_ref(change.get("address", "")),
                        evidence={"protocol": protocol, "full_range": True, "cidr": "0.0.0.0/0"},
                        recommendation="Restrict egress traffic to specific destination CIDRs and ports using the principle of least privilege.",
                        suggested_fix='egress {\n  from_port = 443\n  to_port = 443\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]\n}',
                    )
        return None

    def _rule_sg_ingress_wide_cidr(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        SG-INGRESS-WIDE-CIDR: Ingress Too Broad
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_security_group", "aws_security_group_rule"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        ingress_rules = after.get("ingress", []) if resource_type == "aws_security_group" else []
        if resource_type == "aws_security_group_rule" and after.get("type") == "ingress":
            ingress_rules = [after]

        # Define sensitive ports
        sensitive_ports = {22, 3389, 5432, 3306, 1433, 27017, 6379, 11211}
        # Define risky ports (non-critical but often misused/exposed)
        risky_ports = {8080, 8443, 9200, 5601, 3000, 5000}

        for rule in ingress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            for cidr in cidr_blocks:
                # Check if CIDR is broader than /24 (and is a public-looking CIDR, simplified check)
                is_broad = False
                mask = int(cidr.split("/")[-1]) if "/" in cidr else 32
                if mask < 24 and not cidr.startswith(("10.", "172.16.", "192.168.")):
                    is_broad = True

                # Case 1: Broad CIDR to sensitive port
                if is_broad and any(p in sensitive_ports for p in range(from_port or 0, (to_port or 0) + 1)):
                    return RiskFinding(
                        risk_id="SG-INGRESS-WIDE-CIDR",
                        title="Wide Ingress to Sensitive Port",
                        severity=Severity.MEDIUM,
                        resource_type=resource_type,
                        resource_ref=self._hash_resource_ref(change.get("address", "")),
                        evidence={"cidr": cidr, "mask": mask, "ports": [from_port, to_port]},
                        recommendation="Restrict ingress to more specific CIDR ranges, ideally /32 or your organization's VPN/Office range.",
                        suggested_fix='cidr_blocks = ["203.0.113.45/32"] # Specific IP',
                    )

                # Case 2: 0.0.0.0/0 to risky port
                if cidr == "0.0.0.0/0" and any(p in risky_ports for p in range(from_port or 0, (to_port or 0) + 1)):
                    return RiskFinding(
                        risk_id="SG-INGRESS-WIDE-CIDR",
                        title="Risky Port Open to World",
                        severity=Severity.MEDIUM,
                        resource_type=resource_type,
                        resource_ref=self._hash_resource_ref(change.get("address", "")),
                        evidence={"cidr": cidr, "risky_port": True, "ports": [from_port, to_port]},
                        recommendation="Restrict access to risky ports (e.g., development/admin UIs) to internal ranges only.",
                        suggested_fix='cidr_blocks = ["10.0.0.0/16"] # Internal range only',
                    )
        return None

    def _rule_nacl_ephemeral_open(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        NACL-EPHEMERAL-OPEN: Ephemeral Ports Open to World
        """
        if change.get("type") != "aws_network_acl_rule":
            return None

        after = change.get("change", {}).get("after", {})
        if not after or after.get("rule_action") != "allow" or after.get("egress") is True:
            return None

        # Check for inbound 1024-65535 from 0.0.0.0/0
        cidr = after.get("cidr_block") or after.get("ipv6_cidr_block")
        if cidr in ["0.0.0.0/0", "::/0"]:
            from_port = after.get("from_port")
            to_port = after.get("to_port")
            if from_port and to_port and from_port <= 1024 and to_port >= 65535:
                return RiskFinding(
                    risk_id="NACL-EPHEMERAL-OPEN",
                    title="Ephemeral Ports Open to World",
                    severity=Severity.HIGH,
                    resource_type="aws_network_acl_rule",
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"cidr": cidr, "range": f"{from_port}-{to_port}"},
                    recommendation="Limit NACL rules to return traffic for required services only. Do not blindly open the entire ephemeral range to the world.",
                    suggested_fix='from_port  = 1024\nto_port    = 65535\ncidr_block = "10.0.0.0/16" # Restricted internal range',
                )
        return None

    def _rule_route_igw_default(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        ROUTE-IGW-DEFAULT: Default Route to Internet
        """
        if change.get("type") != "aws_route":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        # Check for 0.0.0.0/0 -> igw-*
        dest = after.get("destination_cidr_block") or after.get("destination_ipv6_cidr_block")
        gateway = after.get("gateway_id", "")
        if dest in ["0.0.0.0/0", "::/0"] and gateway.startswith("igw-"):
            # Check address for "private" label (simple heuristic)
            address = change.get("address", "").lower()
            if "private" in address:
                return RiskFinding(
                    risk_id="ROUTE-IGW-DEFAULT",
                    title="Default Route to IGW in Private Subnet",
                    severity=Severity.CRITICAL,
                    resource_type="aws_route",
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"destination": dest, "gateway": gateway},
                    recommendation="Private subnets should use a NAT Gateway for outbound traffic, not an Internet Gateway.",
                    suggested_fix="gateway_id = aws_nat_gateway.example.id",
                )
        return None

    def _rule_vpc_peering_open(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        VPC-PEERING-OPEN: Risky Peering Routes
        """
        if change.get("type") != "aws_route":
            return None

        after = change.get("change", {}).get("after", {})
        if not after or not after.get("vpc_peering_connection_id"):
            return None

        # Simplified: flag if peering route is added to a very broad CIDR
        dest = after.get("destination_cidr_block", "")
        if dest.endswith("/8") or dest.endswith("/12") or dest.endswith("/16"):
            return RiskFinding(
                risk_id="VPC-PEERING-OPEN",
                title="Broad VPC Peering Route",
                severity=Severity.MEDIUM,
                resource_type="aws_route",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"vpc_peering_id": after.get("vpc_peering_connection_id"), "destination": dest},
                recommendation="Use specific CIDR routes for VPC peering to minimize the reachable surface between VPCs.",
                suggested_fix='destination_cidr_block = "10.0.1.0/24" # Specific subnet',
            )
        return None

    def _rule_tgw_attach_unrestricted(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        TGW-ATTACH-UNRESTRICTED: TGW Attachment Without Controls
        """
        if change.get("type") != "aws_route":
            return None

        after = change.get("change", {}).get("after", {})
        if not after or not after.get("transit_gateway_id"):
            return None

        dest = after.get("destination_cidr_block", "")
        if dest in ["0.0.0.0/0", "::/0"]:
            return RiskFinding(
                risk_id="TGW-ATTACH-UNRESTRICTED",
                title="Broad Transit Gateway Route",
                severity=Severity.HIGH,
                resource_type="aws_route",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"tgw_id": after.get("transit_gateway_id"), "destination": dest},
                recommendation="Ensure Transit Gateway routing is restricted to known internal CIDRs. Do not route all traffic to a TGW without inspecting it (e.g., in a security VPC).",
                suggested_fix='destination_cidr_block = "10.0.0.0/8" # Internal VPC ranges',
            )
        return None

    # ========== Phase 2: Logging & Monitoring Rules ==========

    def _rule_vpc_flowlogs_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        VPC-FLOWLOGS-OFF: VPC Flow Logs Disabled
        """
        if change.get("type") != "aws_flow_log":
            return None

        actions = change.get("change", {}).get("actions", [])
        if "delete" in actions:
            return RiskFinding(
                risk_id="VPC-FLOWLOGS-OFF",
                title="VPC Flow Log Resource Removed",
                severity=Severity.HIGH,
                resource_type="aws_flow_log",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"deleted": True},
                recommendation="Enable VPC Flow Logs for network monitoring and security analysis.",
                suggested_fix='resource "aws_flow_log" "example" {\n  iam_role_arn    = aws_iam_role.example.arn\n  log_destination = aws_cloudwatch_log_group.example.arn\n  traffic_type    = "ALL"\n  vpc_id          = aws_vpc.example.id\n}',
            )
        return None

    def _rule_guardduty_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        GUARDDUTY-OFF: GuardDuty Disabled
        """
        if change.get("type") != "aws_guardduty_detector":
            return None

        change_data = change.get("change", {})
        actions = change_data.get("actions", [])
        after = change_data.get("after", {})

        if "delete" in actions or (after and after.get("enable") is False):
            return RiskFinding(
                risk_id="GUARDDUTY-OFF",
                title="GuardDuty Disabled or Removed",
                severity=Severity.HIGH,
                resource_type="aws_guardduty_detector",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"disabled_or_deleted": True},
                recommendation="GuardDuty should be enabled in all active and inactive regions for threat detection.",
                suggested_fix='resource "aws_guardduty_detector" "example" {\n  enable = true\n}',
            )
        return None

    def _rule_securityhub_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        SECURITYHUB-OFF: Security Hub Disabled
        """
        if change.get("type") not in ["aws_securityhub_account", "aws_securityhub_standards_subscription"]:
            return None

        if "delete" in change.get("change", {}).get("actions", []):
            return RiskFinding(
                risk_id="SECURITYHUB-OFF",
                title="Security Hub Standards or Account Disabled",
                severity=Severity.MEDIUM,
                resource_type=change.get("type"),
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"deleted": True},
                recommendation="Maintain Security Hub subscriptions for continuous compliance monitoring.",
                suggested_fix='resource "aws_securityhub_account" "example" {}\n\nresource "aws_securityhub_standards_subscription" "cis" {\n  depends_on    = [aws_securityhub_account.example]\n  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"\n}',
            )
        return None

    def _rule_config_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        CONFIG-OFF: AWS Config Recorder Disabled
        """
        if change.get("type") != "aws_config_configuration_recorder":
            return None

        if "delete" in change.get("change", {}).get("actions", []):
            return RiskFinding(
                risk_id="CONFIG-OFF",
                title="AWS Config Recorder Removed",
                severity=Severity.HIGH,
                resource_type="aws_config_configuration_recorder",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"deleted": True},
                recommendation="Enable AWS Config for resource relationship tracking and compliance history.",
                suggested_fix='resource "aws_config_configuration_recorder" "example" {\n  name     = "example"\n  role_arn = aws_iam_role.example.arn\n}',
            )
        return None

    def _rule_loggroup_retention_infinite(
        self, change: dict[str, Any], plan_json: dict[str, Any]
    ) -> RiskFinding | None:
        """
        LOGGROUP-RETENTION-INFINITE: No Log Retention
        """
        if change.get("type") != "aws_cloudwatch_log_group":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        retention = after.get("retention_in_days")
        if retention is None or retention == 0:
            return RiskFinding(
                risk_id="LOGGROUP-RETENTION-INFINITE",
                title="Infinite CloudWatch Log Retention",
                severity=Severity.MEDIUM,
                resource_type="aws_cloudwatch_log_group",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"retention_days": 0},
                recommendation="Configure a log retention period (e.g., 30, 90, or 365 days) to manage costs and comply with data lifecycle policies.",
                suggested_fix="retention_in_days = 90",
            )
        return None

    def _rule_cloudtrail_log_validation_off(
        self, change: dict[str, Any], plan_json: dict[str, Any]
    ) -> RiskFinding | None:
        """
        CLOUDTRAIL-NO-LOGVALIDATION: Log File Validation Disabled
        """
        if change.get("type") != "aws_cloudtrail":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("enable_log_file_validation") is False:
            return RiskFinding(
                risk_id="CLOUDTRAIL-NO-LOGVALIDATION",
                title="CloudTrail Log File Validation Disabled",
                severity=Severity.MEDIUM,
                resource_type="aws_cloudtrail",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"log_validation_enabled": False},
                recommendation="Enable log file validation to ensure the integrity of CloudTrail logs.",
                suggested_fix="enable_log_file_validation = true",
            )
        return None

    def _rule_cloudtrail_no_kms(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        CLOUDTRAIL-NO-KMS: CloudTrail Not Encrypted with KMS
        """
        if change.get("type") != "aws_cloudtrail":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if not after.get("kms_key_id"):
            return RiskFinding(
                risk_id="CLOUDTRAIL-NO-KMS",
                title="CloudTrail Logs Not Encrypted with Customer KMS Key",
                severity=Severity.HIGH,
                resource_type="aws_cloudtrail",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"kms_missing": True},
                recommendation="Use a Customer Managed Key (CMK) in KMS to encrypt CloudTrail logs for enhanced security control.",
                suggested_fix='kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"',
            )
        return None

    # ========== Phase 3: Data Protection & Encryption Rules ==========

    def _rule_kms_key_rotation_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        KMS-KEY-ROTATION-OFF: KMS Rotation Disabled
        """
        if change.get("type") != "aws_kms_key":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("enable_key_rotation") is False:
            return RiskFinding(
                risk_id="KMS-KEY-ROTATION-OFF",
                title="KMS Key Rotation Disabled",
                severity=Severity.MEDIUM,
                resource_type="aws_kms_key",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"rotation_enabled": False},
                recommendation="Enable automatic key rotation for Customer Managed Keys to improve security posture.",
                suggested_fix="enable_key_rotation = true",
            )
        return None

    def _rule_kms_policy_open_account(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        KMS-POLICY-OPEN-ACCOUNT: KMS Key Policy Too Broad
        """
        if change.get("type") != "aws_kms_key":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        policy = after.get("policy", "")
        if isinstance(policy, str) and '"Principal":"*"' in policy.replace(" ", ""):
            return RiskFinding(
                risk_id="KMS-POLICY-OPEN-ACCOUNT",
                title="KMS Key Policy Allows Public Principal",
                severity=Severity.CRITICAL,
                resource_type="aws_kms_key",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"principal_star": True},
                recommendation="Restrict KMS key policies to specific IAM roles or accounts. Never use Principal: '*' in a key policy.",
                suggested_fix='statement {\n  sid    = "Enable IAM User Permissions"\n  effect = "Allow"\n  principals {\n    type        = "AWS"\n    identifiers = ["arn:aws:iam::123456789012:root"]\n  }\n  actions   = ["kms:*"]\n  resources = ["*"]\n}',
            )
        return None

    def _rule_ecr_scan_on_push_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        ECR-SCAN-ON-PUSH-OFF: ECR Scan on Push Disabled
        """
        if change.get("type") != "aws_ecr_repository":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        scanning_config = after.get("image_scanning_configuration", [])
        if scanning_config and scanning_config[0].get("scan_on_push") is False:
            return RiskFinding(
                risk_id="ECR-SCAN-ON-PUSH-OFF",
                title="ECR Image Scanning Disabled",
                severity=Severity.MEDIUM,
                resource_type="aws_ecr_repository",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"scan_on_push": False},
                recommendation="Enable scan on push for ECR repositories to detect vulnerabilities in container images.",
                suggested_fix="image_scanning_configuration {\n  scan_on_push = true\n}",
            )
        return None

    def _rule_ecr_public_repo(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        ECR-PUBLIC-REPO: ECR Public Repository
        """
        if change.get("type") != "aws_ecrpublic_repository":
            return None

        if "create" in change.get("change", {}).get("actions", []):
            return RiskFinding(
                risk_id="ECR-PUBLIC-REPO",
                title="Public ECR Repository Created",
                severity=Severity.CRITICAL,
                resource_type="aws_ecrpublic_repository",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"public": True},
                recommendation="Ensure container images intended for internal use are not stored in public ECR repositories.",
                suggested_fix='# Use private ECR repository instead:\n# resource "aws_ecr_repository" "private" {\n#   name = "example"\n# }',
            )
        return None

    def _rule_s3_versioning_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        S3-VERSIONING-OFF: S3 Versioning Disabled
        """
        if change.get("type") != "aws_s3_bucket_versioning":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        status = after.get("versioning_configuration", [{}])[0].get("status")
        if status in ["Suspended", "Disabled"]:
            return RiskFinding(
                risk_id="S3-VERSIONING-OFF",
                title="S3 Versioning Disabled",
                severity=Severity.MEDIUM,
                resource_type="aws_s3_bucket_versioning",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"status": status},
                recommendation="Enable versioning on critical S3 buckets to protect against accidental deletions or overwrites.",
                suggested_fix='versioning_configuration {\n  status = "Enabled"\n}',
            )
        return None

    def _rule_ddb_pitr_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        DDB-PITR-OFF: DynamoDB PITR Disabled
        """
        if change.get("type") != "aws_dynamodb_table":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        pitr = after.get("point_in_time_recovery", [])
        if pitr and pitr[0].get("enabled") is False:
            return RiskFinding(
                risk_id="DDB-PITR-OFF",
                title="DynamoDB Point-in-Time Recovery Disabled",
                severity=Severity.HIGH,
                resource_type="aws_dynamodb_table",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"pitr_enabled": False},
                recommendation="Enable PITR for production DynamoDB tables to allow recovery from accidental data modifications.",
                suggested_fix="point_in_time_recovery {\n  enabled = true\n}",
            )
        return None

    def _rule_sqs_sse_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        SQS-SSE-OFF: SQS Not Encrypted
        """
        if change.get("type") != "aws_sqs_queue":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if not after.get("kms_master_key_id") and not after.get("sqs_managed_sse_enabled"):
            return RiskFinding(
                risk_id="SQS-SSE-OFF",
                title="SQS Queue Server-Side Encryption Disabled",
                severity=Severity.MEDIUM,
                resource_type="aws_sqs_queue",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"encryption_missing": True},
                recommendation="Enable SSE for SQS queues using either SQS-managed keys or KMS CMKs.",
                suggested_fix="sqs_managed_sse_enabled = true",
            )
        return None

    def _rule_sns_sse_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        SNS-SSE-OFF: SNS Not Encrypted
        """
        if change.get("type") != "aws_sns_topic":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if not after.get("kms_master_key_id"):
            return RiskFinding(
                risk_id="SNS-SSE-OFF",
                title="SNS Topic Encryption Disabled",
                severity=Severity.MEDIUM,
                resource_type="aws_sns_topic",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"kms_missing": True},
                recommendation="Configure a KMS key for SNS topics to encrypt message data at rest.",
                suggested_fix='kms_master_key_id = "alias/aws/sns" # Or a CMK ARN',
            )
        return None

    # ========== Phase 4: Destructive & Safety Controls Rules ==========

    def _rule_rds_deletion_protection_off(
        self, change: dict[str, Any], plan_json: dict[str, Any]
    ) -> RiskFinding | None:
        """
        RDS-DELETION-PROTECTION-OFF: RDS Deletion Protection Disabled
        """
        if change.get("type") != "aws_db_instance":
            return None

        after = change.get("change", {}).get("after", {})
        before = change.get("change", {}).get("before", {})
        if not after:
            return None

        # Detect change from true -> false or explicitly set to false
        if after.get("deletion_protection") is False:
            severity = Severity.HIGH if before and before.get("deletion_protection") is True else Severity.MEDIUM
            return RiskFinding(
                risk_id="RDS-DELETION-PROTECTION-OFF",
                title="RDS Deletion Protection Disabled",
                severity=severity,
                resource_type="aws_db_instance",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={
                    "deletion_protection": False,
                    "switched_off": (before and before.get("deletion_protection") is True),
                },
                recommendation="Enable deletion protection for production databases to prevent accidental removal.",
                suggested_fix="deletion_protection = true",
            )
        return None

    def _rule_rds_backup_retention_low(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        RDS-BACKUP-RETENTION-LOW: RDS Backup Retention Too Low
        """
        if change.get("type") != "aws_db_instance":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        retention = after.get("backup_retention_period", 0)
        if retention < 7:
            return RiskFinding(
                risk_id="RDS-BACKUP-RETENTION-LOW",
                title="RDS Backup Retention Period Too Short",
                severity=Severity.MEDIUM,
                resource_type="aws_db_instance",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"retention_period": retention},
                recommendation="Set backup retention to at least 7 days for production databases to ensure point-in-time recovery options.",
                suggested_fix="backup_retention_period = 7",
            )
        return None

    def _rule_rds_public_snapshots(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        RDS-PUBLIC-SNAPSHOTS: RDS Snapshot Public Sharing
        """
        if change.get("type") != "aws_db_snapshot_attribute":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("attribute_name") == "restore" and "all" in str(after.get("values", [])):
            return RiskFinding(
                risk_id="RDS-PUBLIC-SNAPSHOTS",
                title="RDS Snapshot Shared Publicly",
                severity=Severity.CRITICAL,
                resource_type="aws_db_snapshot_attribute",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"public_restore": True},
                recommendation="Never share database snapshots with 'all'. Restrict sharing to specific AWS account IDs.",
                suggested_fix='values = ["123456789012"] # Specific Account ID',
            )
        return None

    def _rule_ebs_snapshot_public(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        EBS-SNAPSHOT-PUBLIC: EBS Snapshot Public Sharing
        """
        # Simplified: check for create_volume_permission with 'all'
        if change.get("type") != "aws_ebs_snapshot_permission":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("group") == "all":
            return RiskFinding(
                risk_id="EBS-SNAPSHOT-PUBLIC",
                title="EBS Snapshot Shared Publicly",
                severity=Severity.CRITICAL,
                resource_type="aws_ebs_snapshot_permission",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"public_group": "all"},
                recommendation="Remove public volume creation permissions from EBS snapshots.",
                suggested_fix='# Do not use group = "all"',
            )
        return None

    def _rule_s3_force_destroy_true(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        S3-FORCE-DESTROY-TRUE: Force Destroy Enabled
        """
        if change.get("type") != "aws_s3_bucket":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("force_destroy") is True:
            return RiskFinding(
                risk_id="S3-FORCE-DESTROY-TRUE",
                title="S3 Bucket Force Destroy Enabled",
                severity=Severity.HIGH,
                resource_type="aws_s3_bucket",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"force_destroy": True},
                recommendation="Disable force_destroy on production buckets to prevent accidental data loss during infrastructure teardowns.",
                suggested_fix="force_destroy = false",
            )
        return None

    def _rule_kms_schedule_delete(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        KMS-SCHEDULE-DELETE: KMS Key Scheduled for Deletion
        """
        if change.get("type") != "aws_kms_key":
            return None

        actions = change.get("change", {}).get("actions", [])
        after = change.get("change", {}).get("after", {})

        if "delete" in actions or (after and after.get("deletion_window_in_days") is not None):
            return RiskFinding(
                risk_id="KMS-SCHEDULE-DELETE",
                title="KMS Key Scheduled for Deletion",
                severity=Severity.HIGH,
                resource_type="aws_kms_key",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={
                    "scheduled_deletion": True,
                    "window": after.get("deletion_window_in_days") if after else "immediate",
                },
                recommendation="Ensure that the KMS key scheduled for deletion is no longer required for decrypting legacy data.",
                suggested_fix="# To prevent deletion, ensure 'deletion_window_in_days' is not set\n# or use 'terraform untaint' if it was marked for deletion.",
            )
        return None

    # ========== Phase 5: Compute & App Exposure Rules ==========

    def _rule_ec2_imdsv1_allowed(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        EC2-IMDSV1-ALLOWED: IMDSv1 Allowed
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_instance", "aws_launch_template"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        # Check metadata_options
        metadata_options = after.get("metadata_options", [])
        if metadata_options:
            tokens = metadata_options[0].get("http_tokens")
            if tokens != "required":
                return RiskFinding(
                    risk_id="EC2-IMDSV1-ALLOWED",
                    title="EC2 Instance Allows IMDSv1",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"http_tokens": tokens or "optional (default)"},
                    recommendation="Enforce IMDSv2 by setting http_tokens = 'required' in metadata_options. IMDSv1 is vulnerable to SSRF-based credential theft.",
                    suggested_fix='metadata_options {\n  http_tokens = "required"\n}',
                )
        return None

    def _rule_ec2_public_ip_assigned(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        EC2-PUBLIC-IP-ASSIGNED: Public IP on Instance
        """
        if change.get("type") != "aws_instance":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("associate_public_ip_address") is True:
            return RiskFinding(
                risk_id="EC2-PUBLIC-IP-ASSIGNED",
                title="EC2 Instance Assigned a Public IP",
                severity=Severity.HIGH,
                resource_type="aws_instance",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"associate_public_ip_address": True},
                recommendation="Avoid assigning public IPs to instances. Use NAT Gateways for outbound access and Load Balancers or Bastion hosts for inbound access.",
                suggested_fix="associate_public_ip_address = false",
            )
        return None

    def _rule_asg_min_size_zero(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        ASG-MIN-SIZE-ZERO: Availability Risk
        """
        if change.get("type") != "aws_autoscaling_group":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("min_size") == 0:
            return RiskFinding(
                risk_id="ASG-MIN-SIZE-ZERO",
                title="Auto Scaling Group Minimum Size is Zero",
                severity=Severity.MEDIUM,
                resource_type="aws_autoscaling_group",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"min_size": 0},
                recommendation="Set a minimum size greater than zero for production services to ensure high availability.",
                suggested_fix="min_size = 1",
            )
        return None

    def _rule_lambda_url_auth_none(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        LAMBDA-URL-AUTH-NONE: Lambda Function URL Public
        """
        if change.get("type") != "aws_lambda_function_url":
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        if after.get("authorization_type") == "NONE":
            return RiskFinding(
                risk_id="LAMBDA-URL-AUTH-NONE",
                title="Lambda Function URL is Publicly Accessible",
                severity=Severity.CRITICAL,
                resource_type="aws_lambda_function_url",
                resource_ref=self._hash_resource_ref(change.get("address", "")),
                evidence={"authorization_type": "NONE"},
                recommendation="Enable AWS_IAM authorization for Lambda function URLs unless public access is explicitly intended and secured via other means.",
                suggested_fix='authorization_type = "AWS_IAM"',
            )
        return None

    def _rule_apigw_open_auth(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        APIGW-OPEN-AUTH: API Gateway Without Auth
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_api_gateway_method", "aws_apigatewayv2_route"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        # v1 Method
        if resource_type == "aws_api_gateway_method":
            auth = after.get("authorization", "NONE")
            if auth == "NONE" and not after.get("api_key_required"):
                return RiskFinding(
                    risk_id="APIGW-OPEN-AUTH",
                    title="API Gateway Method Lacks Authorization",
                    severity=Severity.HIGH,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"authorization": auth},
                    recommendation="Configure an authorizer (IAM/Cognito/Lambda) or require an API key for API Gateway methods.",
                    suggested_fix='authorization = "AWS_IAM" # Or "CUSTOM", "COGNITO_USER_POOLS"',
                )

        # v2 Route
        if resource_type == "aws_apigatewayv2_route":
            auth_type = after.get("authorization_type", "NONE")
            if auth_type == "NONE":
                return RiskFinding(
                    risk_id="APIGW-OPEN-AUTH",
                    title="API Gateway v2 Route Lacks Authorization",
                    severity=Severity.HIGH,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"authorization_type": auth_type},
                    recommendation="Configure an authorization type for API Gateway v2 routes.",
                    suggested_fix='authorization_type = "AWS_IAM"',
                )
        return None

    def _rule_alb_accesslogs_off(self, change: dict[str, Any], plan_json: dict[str, Any]) -> RiskFinding | None:
        """
        ALB-ACCESSLOGS-OFF: ALB Access Logs Disabled
        """
        resource_type = change.get("type", "")
        if resource_type not in ["aws_lb", "aws_alb"]:
            return None

        after = change.get("change", {}).get("after", {})
        if not after:
            return None

        access_logs = after.get("access_logs", [])
        if access_logs:
            if access_logs[0].get("enabled") is False:
                return RiskFinding(
                    risk_id="ALB-ACCESSLOGS-OFF",
                    title="ALB Access Logging Disabled",
                    severity=Severity.MEDIUM,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get("address", "")),
                    evidence={"access_logs_enabled": False},
                    recommendation="Enable access logging for ALBs to record information about the requests sent to your load balancer.",
                    suggested_fix='access_logs {\n  bucket  = aws_s3_bucket.logs.id\n  prefix  = "alb-logs"\n  enabled = true\n}',
                )
        else:
            # If completely missing access_logs block (simplified detection)
            pass
        return None
