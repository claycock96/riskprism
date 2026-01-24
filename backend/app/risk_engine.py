import hashlib
from typing import Dict, Any, List, Optional
import logging

from app.models import RiskFinding, Severity, ResourceChange

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
        ]

    def analyze(
        self,
        plan_json: Dict[str, Any],
        diff_skeleton: List[ResourceChange],
        max_findings: int = 50
    ) -> List[RiskFinding]:
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

        resource_changes = plan_json.get('resource_changes', [])

        for change in resource_changes:
            # Skip no-op changes
            actions = change.get('change', {}).get('actions', [])
            if actions == ['no-op']:
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
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        findings.sort(key=lambda f: severity_order[f.severity])

        logger.info(f"Risk analysis complete: {len(findings)} findings")
        return findings[:max_findings]

    def _hash_resource_ref(self, address: str) -> str:
        """Generate stable hash for resource address"""
        hash_obj = hashlib.sha256(address.encode('utf-8'))
        return f"res_{hash_obj.hexdigest()[:10]}"

    # ========== Risk Rules ==========

    def _rule_sg_open_ingress(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        SG-OPEN-INGRESS: Security group allows public ingress

        Triggers on:
        - aws_security_group with ingress rules containing 0.0.0.0/0 or ::/0
        - aws_security_group_rule with public CIDR
        """
        resource_type = change.get('type', '')

        if resource_type not in ['aws_security_group', 'aws_security_group_rule']:
            return None

        change_data = change.get('change', {})
        after = change_data.get('after', {})

        if not after:
            return None

        # Check ingress rules
        ingress_rules = after.get('ingress', []) if resource_type == 'aws_security_group' else []

        # For aws_security_group_rule, check the rule itself
        if resource_type == 'aws_security_group_rule':
            rule_type = after.get('type')
            if rule_type == 'ingress':
                ingress_rules = [after]

        public_cidrs = []
        exposed_ports = []

        for rule in ingress_rules:
            cidr_blocks = rule.get('cidr_blocks', [])
            ipv6_cidr_blocks = rule.get('ipv6_cidr_blocks', [])

            # Check for public CIDRs
            if '0.0.0.0/0' in cidr_blocks or '::/0' in ipv6_cidr_blocks:
                public_cidrs.append('public')

                # Extract ports
                from_port = rule.get('from_port')
                to_port = rule.get('to_port')

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
            resource_ref=self._hash_resource_ref(change.get('address', '')),
            evidence={
                "public_cidr": True,
                "exposed_ports": exposed_ports if exposed_ports else ["unspecified"],
                "critical_port_exposed": any(p in critical_ports for p in exposed_ports)
            },
            recommendation="Restrict CIDR blocks to known IP ranges. For SSH/RDP, use AWS Systems Manager Session Manager or a bastion host. For databases, ensure they are in private subnets with security groups allowing only application tier access.",
            suggested_fix="ingress {\n  from_port   = 443\n  to_port     = 443\n  protocol    = \"tcp\"\n  cidr_blocks = [\"10.0.0.0/16\"] # Restricted range\n}",
            changed_paths=None
        )

    def _rule_s3_public_acl_or_policy(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        S3-PUBLIC-ACL-OR-POLICY: S3 bucket has public access via policy or ACL
        """
        resource_type = change.get('type', '')

        if resource_type not in ['aws_s3_bucket_policy', 'aws_s3_bucket_acl', 'aws_s3_bucket']:
            return None

        change_data = change.get('change', {})
        after = change_data.get('after', {})

        if not after:
            return None

        # Check bucket policy for Principal: "*"
        if resource_type == 'aws_s3_bucket_policy':
            policy = after.get('policy', '')
            if isinstance(policy, str) and '"Principal":"*"' in policy.replace(' ', ''):
                return RiskFinding(
                    risk_id="S3-PUBLIC-ACL-OR-POLICY",
                    title="S3 bucket policy allows public access",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get('address', '')),
                    evidence={
                        "principal_star": True,
                        "public_read_risk": True
                    },
                    recommendation="Remove Principal: '*' from bucket policy or add strict conditions. Enable S3 Block Public Access settings. Use CloudFront with OAC for public content distribution.",
                    suggested_fix="statement {\n  principals {\n    type        = \"AWS\"\n    identifiers = [\"arn:aws:iam::123456789012:role/MyRole\"]\n  }\n  actions = [\"s3:GetObject\"]\n}",
                    changed_paths=None
                )

        # Check bucket ACL
        if resource_type in ['aws_s3_bucket_acl', 'aws_s3_bucket']:
            acl = after.get('acl', '')
            if acl in ['public-read', 'public-read-write']:
                return RiskFinding(
                    risk_id="S3-PUBLIC-ACL-OR-POLICY",
                    title="S3 bucket ACL allows public access",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get('address', '')),
                    evidence={
                        "public_acl": acl,
                        "public_write": acl == 'public-read-write'
                    },
                    recommendation="Change ACL to 'private'. Enable S3 Block Public Access. Use bucket policies with specific principals for controlled sharing.",
                    suggested_fix="acl = \"private\"",
                    changed_paths=None
                )

        return None

    def _rule_s3_pab_removed(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        S3-PAB-REMOVED: S3 Public Access Block settings disabled or removed
        """
        resource_type = change.get('type', '')

        if resource_type != 'aws_s3_bucket_public_access_block':
            return None

        change_data = change.get('change', {})
        actions = change_data.get('actions', [])
        before = change_data.get('before', {})
        after = change_data.get('after', {})

        # Check for deletion
        if 'delete' in actions:
            return RiskFinding(
                risk_id="S3-PAB-REMOVED",
                title="S3 Public Access Block removed",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"pab_removed": True},
                recommendation="Keep S3 Block Public Access enabled unless explicitly required for public content. Document exceptions.",
                suggested_fix="resource \"aws_s3_bucket_public_access_block\" \"example\" {\n  bucket = aws_s3_bucket.example.id\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
                changed_paths=None
            )

        # Check for disabling settings
        if after:
            disabled_settings = []
            for setting in ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets']:
                if after.get(setting) is False:
                    disabled_settings.append(setting)

            if disabled_settings:
                return RiskFinding(
                    risk_id="S3-PAB-REMOVED",
                    title="S3 Public Access Block settings disabled",
                    severity=Severity.HIGH,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get('address', '')),
                    evidence={
                        "pab_disabled": True,
                        "disabled_settings": disabled_settings
                    },
                    recommendation="Enable all Block Public Access settings unless public access is explicitly required and approved.",
                    suggested_fix="block_public_acls       = true\nblock_public_policy     = true\nignore_public_acls      = true\nrestrict_public_buckets = true",
                    changed_paths=None
                )

        return None

    def _rule_s3_encryption_removed(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        S3-ENCRYPTION-REMOVED: S3 bucket encryption disabled
        """
        resource_type = change.get('type', '')

        if resource_type != 'aws_s3_bucket_server_side_encryption_configuration':
            return None

        change_data = change.get('change', {})
        actions = change_data.get('actions', [])

        if 'delete' in actions:
            return RiskFinding(
                risk_id="S3-ENCRYPTION-REMOVED",
                title="S3 bucket encryption removed",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"sse_removed": True},
                recommendation="Enable server-side encryption. Use SSE-KMS for sensitive data. Consider compliance requirements.",
                suggested_fix="resource \"aws_s3_bucket_server_side_encryption_configuration\" \"example\" {\n  bucket = aws_s3_bucket.example.id\n\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = \"AES256\"\n    }\n  }\n}",
                changed_paths=None
            )

        return None

    def _rule_rds_publicly_accessible(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        RDS-PUBLICLY-ACCESSIBLE: RDS instance exposed to public internet
        """
        resource_type = change.get('type', '')

        if resource_type != 'aws_db_instance':
            return None

        change_data = change.get('change', {})
        after = change_data.get('after', {})

        if after and after.get('publicly_accessible') is True:
            return RiskFinding(
                risk_id="RDS-PUBLICLY-ACCESSIBLE",
                title="RDS instance is publicly accessible",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"publicly_accessible": True},
                recommendation="Set publicly_accessible to false. Place RDS in private subnets. Use VPC security groups to restrict access to application tier only.",
                suggested_fix="publicly_accessible = false",
                changed_paths=None
            )

        return None

    def _rule_rds_encryption_off(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        RDS-ENCRYPTION-OFF: RDS instance encryption disabled
        """
        resource_type = change.get('type', '')

        if resource_type != 'aws_db_instance':
            return None

        change_data = change.get('change', {})
        after = change_data.get('after', {})

        if after and after.get('storage_encrypted') is False:
            return RiskFinding(
                risk_id="RDS-ENCRYPTION-OFF",
                title="RDS instance storage encryption disabled",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"encryption_disabled": True},
                recommendation="Enable storage_encrypted. Note: existing instances require snapshot, restore to new encrypted instance. Plan for maintenance window.",
                suggested_fix="storage_encrypted = true",
                changed_paths=None
            )

        return None

    def _rule_iam_admin_wildcard(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        IAM-ADMIN-WILDCARD: IAM policy uses wildcard actions or resources
        """
        resource_type = change.get('type', '')

        if resource_type not in ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy']:
            return None

        change_data = change.get('change', {})
        after = change_data.get('after', {})

        if not after:
            return None

        policy = after.get('policy', '')

        if not isinstance(policy, str):
            return None

        # Simple heuristic: check for Action: "*" or broad service wildcards
        dangerous_patterns = ['"Action":"*"', '"Action":["*"]', '"iam:*"', '"Resource":"*"']

        if any(pattern.replace(' ', '') in policy.replace(' ', '') for pattern in dangerous_patterns):
            return RiskFinding(
                risk_id="IAM-ADMIN-WILDCARD",
                title="IAM policy contains wildcard permissions",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={
                    "action_wildcard": True,
                    "admin_risk": True
                },
                recommendation="Scope IAM actions and resources to least privilege. Avoid Action: '*' and Resource: '*'. Use separate break-glass admin roles with MFA and monitoring.",
                suggested_fix="statement {\n  actions   = [\"ec2:Describe*\", \"s3:ListBucket\"]\n  resources = [\"*\"]\n  # Prefer specific resource ARNs where possible\n}",
                changed_paths=None
            )

        return None

    def _rule_iam_managed_policy_attachment(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        IAM-MANAGED-POLICY: Dangerous AWS managed policy attachment
        """
        resource_type = change.get('type', '')

        # Check for policy attachment resources
        if resource_type not in [
            'aws_iam_role_policy_attachment',
            'aws_iam_user_policy_attachment',
            'aws_iam_group_policy_attachment'
        ]:
            return None

        change_data = change.get('change', {})
        after = change_data.get('after', {})

        if not after:
            return None

        policy_arn = after.get('policy_arn', '')

        if not isinstance(policy_arn, str):
            return None

        # List of dangerous AWS managed policies
        dangerous_policies = {
            'AdministratorAccess': 'Grants full access to all AWS services and resources',
            'PowerUserAccess': 'Grants full access except IAM and Organizations management',
            'IAMFullAccess': 'Grants full access to IAM, enabling privilege escalation',
            'SecurityAudit': 'Grants read access to security-related AWS resources',
            'SystemAdministrator': 'Grants full access to AWS services except billing',
        }

        # Check if the policy ARN matches any dangerous policies
        for policy_name, description in dangerous_policies.items():
            if policy_name in policy_arn:
                # Determine severity based on the policy
                if policy_name in ['AdministratorAccess', 'IAMFullAccess']:
                    severity = Severity.CRITICAL
                elif policy_name == 'PowerUserAccess':
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                return RiskFinding(
                    risk_id="IAM-MANAGED-POLICY",
                    title=f"Dangerous AWS managed policy attached: {policy_name}",
                    severity=severity,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get('address', '')),
                    evidence={
                        "policy_arn": policy_arn,
                        "policy_name": policy_name,
                        "description": description,
                        "action": change_data.get('actions', [])
                    },
                    recommendation=f"Review the need for {policy_name}. This policy grants excessive permissions. Consider using a custom policy with least-privilege permissions or a more restrictive AWS managed policy. For break-glass admin access, use a separate role with MFA and strict approval workflows.",
                    suggested_fix="# Replace with a more restrictive managed policy or a custom policy\npolicy_arn = \"arn:aws:iam::aws:policy/ReadOnlyAccess\"",
                    changed_paths=None
                )

        return None

    def _rule_cloudtrail_disabled(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        CT-LOGGING-DISABLED: CloudTrail logging disabled or removed
        """
        resource_type = change.get('type', '')

        if resource_type != 'aws_cloudtrail':
            return None

        change_data = change.get('change', {})
        actions = change_data.get('actions', [])
        after = change_data.get('after', {})

        # Check for deletion
        if 'delete' in actions:
            return RiskFinding(
                risk_id="CT-LOGGING-DISABLED",
                title="CloudTrail logging removed",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"cloudtrail_removed": True},
                recommendation="Maintain CloudTrail logging for audit and compliance. Use organization trails for multi-account coverage.",
                suggested_fix="# Do not delete aws_cloudtrail resources in production",
                changed_paths=None
            )

        # Check if logging is disabled
        if after and after.get('enable_logging') is False:
            return RiskFinding(
                risk_id="CT-LOGGING-DISABLED",
                title="CloudTrail logging disabled",
                severity=Severity.CRITICAL,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"cloudtrail_disabled": True},
                recommendation="Enable CloudTrail logging. Ensure logs are protected with encryption and access controls.",
                suggested_fix="enable_logging = true",
                changed_paths=None
            )

        return None

    def _rule_iam_passrole_wildcard(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        IAM-PASSROLE-BROAD: iam:PassRole allowed on wildcard resource
        """
        resource_type = change.get('type', '')
        if resource_type not in ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy']:
            return None

        after = change.get('change', {}).get('after', {})
        if not after or not isinstance(after.get('policy'), str):
            return None

        policy = after.get('policy', '').replace(' ', '')
        if '"Action":"iam:PassRole"' in policy or '"Action":["iam:PassRole"]' in policy:
            if '"Resource":"*"' in policy or '"Resource":["*"]' in policy:
                return RiskFinding(
                    risk_id="IAM-PASSROLE-BROAD",
                    title="IAM policy allows iam:PassRole on all resources",
                    severity=Severity.CRITICAL,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get('address', '')),
                    evidence={"action": "iam:PassRole", "resource_wildcard": True},
                    recommendation="Restrict iam:PassRole to specific role ARNs. Wildcard PassRole allows an attacker to pass ANY role to a service, leading to full privilege escalation.",
                    suggested_fix="statement {\n  actions   = [\"iam:PassRole\"]\n  resources = [\"arn:aws:iam::123456789012:role/SpecificServiceRole\"]\n}",
                    changed_paths=None
                )
        return None

    def _rule_sts_assumerole_wildcard(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        STS-ASSUMEROLE-WILDCARD: sts:AssumeRole allowed on wildcard resource
        """
        resource_type = change.get('type', '')
        if resource_type not in ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy']:
            return None

        after = change.get('change', {}).get('after', {})
        if not after or not isinstance(after.get('policy'), str):
            return None

        policy = after.get('policy', '').replace(' ', '')
        if '"Action":"sts:AssumeRole"' in policy or '"Action":["sts:AssumeRole"]' in policy:
            if '"Resource":"*"' in policy or '"Resource":["*"]' in policy:
                return RiskFinding(
                    risk_id="STS-ASSUMEROLE-WILDCARD",
                    title="IAM policy allows sts:AssumeRole on all resources",
                    severity=Severity.HIGH,
                    resource_type=resource_type,
                    resource_ref=self._hash_resource_ref(change.get('address', '')),
                    evidence={"action": "sts:AssumeRole", "resource_wildcard": True},
                    recommendation="Restrict sts:AssumeRole to specific role ARNs. Broad AssumeRole permissions increase the blast radius of compromised credentials.",
                    suggested_fix="statement {\n  actions   = [\"sts:AssumeRole\"]\n  resources = [\"arn:aws:iam::123456789012:role/SpecificCrossAccountRole\"]\n}",
                    changed_paths=None
                )
        return None

    def _rule_nacl_allow_all(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        NACL-ALLOW-ALL: Network ACL allows all traffic from any source
        """
        resource_type = change.get('type', '')
        if resource_type != 'aws_network_acl_rule':
            return None

        after = change.get('change', {}).get('after', {})
        if not after:
            return None

        # rule_action="allow", protocol="-1" (all), cidr_block="0.0.0.0/0"
        if (after.get('rule_action') == 'allow' and 
            str(after.get('protocol')) == '-1' and 
            (after.get('cidr_block') == '0.0.0.0/0' or after.get('ipv6_cidr_block') == '::/0')):
            
            return RiskFinding(
                risk_id="NACL-ALLOW-ALL",
                title="Network ACL allows all traffic from any source",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={
                    "rule_action": "allow",
                    "protocol": "all",
                    "cidr_block": after.get('cidr_block') or after.get('ipv6_cidr_block')
                },
                recommendation="Restrict Network ACL rules to specific protocols and CIDR blocks. Prefer Security Groups for stateful traffic control.",
                suggested_fix="rule_action = \"allow\"\nprotocol    = \"tcp\"\nfrom_port   = 443\nto_port     = 443\ncidr_block  = \"10.0.0.0/16\"",
                changed_paths=None
            )
        return None

    def _rule_lb_internet_facing(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        LB-INTERNET-FACING: Load balancer is internet-facing
        """
        resource_type = change.get('type', '')
        if resource_type not in ['aws_lb', 'aws_alb', 'aws_elb']:
            return None

        after = change.get('change', {}).get('after', {})
        if not after:
            return None

        # aws_lb/aws_alb uses 'internal', aws_elb uses 'internal'
        is_internal = after.get('internal')
        
        # If internal is false (or explicitly set to false), it's internet-facing
        if is_internal is False:
            return RiskFinding(
                risk_id="LB-INTERNET-FACING",
                title="Load balancer is internet-facing",
                severity=Severity.MEDIUM,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"internal": False},
                recommendation="Ensure the load balancer is intended to be public. Use WAF and restrictive Security Groups to protect public endpoints.",
                suggested_fix="internal = true",
                changed_paths=None
            )
        return None

    def _rule_ebs_encryption_off(
        self,
        change: Dict[str, Any],
        plan_json: Dict[str, Any]
    ) -> Optional[RiskFinding]:
        """
        EBS-ENCRYPTION-OFF: EBS volume encryption is disabled
        """
        resource_type = change.get('type', '')
        if resource_type != 'aws_ebs_volume':
            return None

        after = change.get('change', {}).get('after', {})
        if not after:
            return None

        if after.get('encrypted') is False:
            return RiskFinding(
                risk_id="EBS-ENCRYPTION-OFF",
                title="EBS volume encryption is disabled",
                severity=Severity.HIGH,
                resource_type=resource_type,
                resource_ref=self._hash_resource_ref(change.get('address', '')),
                evidence={"encrypted": False},
                recommendation="Enable EBS encryption to protect data at rest. You can enable account-level default encryption in the AWS region.",
                suggested_fix="encrypted = true",
                changed_paths=None
            )
        return None
