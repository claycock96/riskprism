import hashlib
import json
import logging
import re
from typing import Any

from app.models import AttributeDiff, PlanSummary, ResourceChange

logger = logging.getLogger(__name__)


class TerraformPlanParser:
    """
    Parses Terraform plan JSON and extracts minimal diff skeleton.

    PRIVACY OWNERSHIP: This class is the single source of truth for Terraform
    data sanitization. All sensitive data filtering happens here during
    extract_diff_skeleton() - the output is safe to send to LLM/storage.

    Key responsibilities:
    - Validate plan JSON structure
    - Extract resource changes
    - Compute changed attribute paths
    - Generate stable hashes for resource references
    - Sanitize sensitive values (passwords, secrets, keys) via denylist
    - Pattern-match and redact embedded secrets in string values
    """

    def __init__(self):
        # Denylist is still used for immediate exclusion of keys
        self.sensitive_keys = {
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "access_key",
            "secret_key",
            "private_key",
            "client_secret",
            "certificate",
            "cert",
            "key_material",
            "user_data",
            "bootstrap",
        }

        # Allowlist of attributes where the VALUE is considered safe to send to LLM/Store
        # Focus on: boolean flags, numeric values, enum-like configs
        # Avoid: identifiers, ARNs, names that reveal infrastructure details
        self.safe_attributes = {
            # === CORE METADATA ===
            "type",
            "action",
            "severity",
            "risk_id",
            "recommendation",
            "total_changes",
            "creates",
            "updates",
            "deletes",
            "replaces",
            "terraform_version",
            "description",
            # === NETWORKING / SECURITY GROUPS ===
            "cidr_blocks",
            "ipv6_cidr_blocks",
            "protocol",
            "from_port",
            "to_port",
            "egress",
            "ingress",
            "self",
            "associate_public_ip_address",
            "map_public_ip_on_launch",
            "enable_dns_support",
            "enable_dns_hostnames",
            "assign_ipv6_address_on_creation",
            # === RDS / DATABASES ===
            "engine",
            "engine_version",
            "instance_class",
            "multi_az",
            "publicly_accessible",
            "storage_type",
            "allocated_storage",
            "max_allocated_storage",
            "port",
            "storage_encrypted",
            "backup_retention_period",
            "backup_window",
            "maintenance_window",
            "deletion_protection",
            "skip_final_snapshot",
            "iam_database_authentication_enabled",
            "performance_insights_enabled",
            "auto_minor_version_upgrade",
            "copy_tags_to_snapshot",
            "monitoring_interval",
            "apply_immediately",
            "allow_major_version_upgrade",
            # === S3 ===
            "acl",
            "force_destroy",
            "versioning",
            "versioning_configuration",
            "mfa_delete",
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
            "sse_algorithm",
            "object_lock_enabled",
            # === EC2 / COMPUTE ===
            "ami",
            "instance_type",
            "monitoring",
            "ebs_optimized",
            "architecture",
            "runtime",
            "handler",
            "memory_size",
            "timeout",
            "encrypted",
            "volume_type",
            "volume_size",
            "iops",
            "throughput",
            "delete_on_termination",
            "disable_api_termination",
            "instance_initiated_shutdown_behavior",
            "http_tokens",  # IMDSv2
            "http_endpoint",
            "http_put_response_hop_limit",
            "tenancy",
            "hibernation",
            "credit_specification",
            # === IAM (structure only, not values) ===
            "effect",
            "path",
            "max_session_duration",
            "force_detach_policies",
            "require_lowercase_characters",
            "require_uppercase_characters",
            "require_numbers",
            "require_symbols",
            "allow_users_to_change_password",
            "max_password_age",
            "password_reuse_prevention",
            "hard_expiry",
            # === ELB / ALB / NLB ===
            "internal",
            "load_balancer_type",
            "ip_address_type",
            "enable_deletion_protection",
            "enable_cross_zone_load_balancing",
            "enable_http2",
            "idle_timeout",
            "drop_invalid_header_fields",
            "desync_mitigation_mode",
            "ssl_policy",
            "target_type",
            "deregistration_delay",
            "slow_start",
            "stickiness",
            "health_check",
            "healthy_threshold",
            "unhealthy_threshold",
            "health_check_interval",
            "health_check_timeout",
            # === LAMBDA ===
            "reserved_concurrent_executions",
            "publish",
            "tracing_mode",
            # === CLOUDWATCH / LOGGING ===
            "retention_in_days",
            "metric_name",
            "namespace",
            "period",
            "statistic",
            "threshold",
            "comparison_operator",
            "evaluation_periods",
            "treat_missing_data",
            "datapoints_to_alarm",
            # === KMS ===
            "enable_key_rotation",
            "key_usage",
            "customer_master_key_spec",
            "deletion_window_in_days",
            "is_enabled",
            "multi_region",
            # === SECRETS / SSM ===
            "recovery_window_in_days",
            "rotation_enabled",
            "data_type",
            "tier",
            # === ECS / EKS ===
            "launch_type",
            "network_mode",
            "requires_compatibilities",
            "cpu",
            "memory",
            "privileged",
            "readonly_root_filesystem",
            "enable_execute_command",
            "endpoint_private_access",
            "endpoint_public_access",
            "enabled_cluster_log_types",
            # === SQS / SNS ===
            "sqs_managed_sse_enabled",
            "visibility_timeout_seconds",
            "message_retention_seconds",
            "receive_wait_time_seconds",
            "fifo_queue",
            "content_based_deduplication",
            "max_message_size",
            "delay_seconds",
            # === DYNAMODB ===
            "billing_mode",
            "read_capacity",
            "write_capacity",
            "point_in_time_recovery",
            "ttl",
            "stream_enabled",
            "stream_view_type",
            "table_class",
            "deletion_protection_enabled",
            # === GENERIC BOOLEAN/STATE FLAGS ===
            "enabled",
            "enable",
            "disabled",
            "active",
            "state",
            "status",
            "version",
        }

        # Regex patterns for common secrets to catch them even in "safe" fields
        self.secret_patterns = [
            re.compile(r"(?i)key-[a-zA-Z0-9]{20,}"),  # Generic key-like string
            re.compile(r"(?i)secret[_-]?key[:=]\s*[^\s]{10,}"),
            re.compile(r"(?i)password[:=]\s*[^\s]{8,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
            re.compile(r"[a-zA-Z0-9+/]{40}"),  # AWS Secret Key (approx)
            re.compile(r"sk_live_[0-9a-zA-Z]{24}"),  # Stripe Secret Key
        ]

    def parse(self, plan_json: dict[str, Any]) -> dict[str, Any]:
        """
        Parse and validate Terraform plan JSON structure.

        Args:
            plan_json: Raw plan JSON from 'terraform show -json tfplan'

        Returns:
            Validated plan structure

        Raises:
            ValueError: If plan JSON is invalid
        """
        if not isinstance(plan_json, dict):
            raise ValueError("plan_json must be a dictionary")

        # Check for required fields
        if "resource_changes" not in plan_json:
            raise ValueError("Missing 'resource_changes' field in plan JSON")

        logger.info(f"Parsed plan with {len(plan_json.get('resource_changes', []))} resource changes")
        return plan_json

    def generate_summary(self, plan_json: dict[str, Any]) -> PlanSummary:
        """
        Generate high-level summary statistics from plan.

        Args:
            plan_json: Parsed plan JSON

        Returns:
            PlanSummary with counts and metadata
        """
        resource_changes = plan_json.get("resource_changes", [])

        creates = 0
        updates = 0
        deletes = 0
        replaces = 0

        for change in resource_changes:
            actions = change.get("change", {}).get("actions", [])

            if "create" in actions and "delete" in actions:
                replaces += 1
            elif "create" in actions:
                creates += 1
            elif "update" in actions:
                updates += 1
            elif "delete" in actions:
                deletes += 1

        terraform_version = plan_json.get("terraform_version")

        return PlanSummary(
            total_changes=creates + updates + deletes + replaces,
            creates=creates,
            updates=updates,
            deletes=deletes,
            replaces=replaces,
            terraform_version=terraform_version,
        )

    def extract_diff_skeleton(self, plan_json: dict[str, Any]) -> list[ResourceChange]:
        """
        Extract minimal diff skeleton from plan.

        This creates a sanitized representation with:
        - Resource type and action
        - Changed attribute paths (keys only, no values)
        - Stable hashed references

        Args:
            plan_json: Parsed plan JSON

        Returns:
            List of ResourceChange objects
        """
        resource_changes = plan_json.get("resource_changes", [])
        skeleton = []

        for change in resource_changes:
            try:
                resource_type = change.get("type", "unknown")
                address = change.get("address", "unknown")
                change_data = change.get("change", {})
                actions = change_data.get("actions", [])

                # Determine primary action
                if "create" in actions and "delete" in actions:
                    action = "replace"
                elif "create" in actions:
                    action = "create"
                elif "update" in actions:
                    action = "update"
                elif "delete" in actions:
                    action = "delete"
                elif "no-op" in actions:
                    continue  # Skip no-op changes
                else:
                    action = "unknown"

                # Extract changed paths and diffs
                before = change_data.get("before", {})
                after = change_data.get("after", {})
                attribute_diffs = self._extract_attribute_diffs(before, after)
                changed_paths = [d.path for d in attribute_diffs]

                # Generate stable hash for resource reference
                resource_ref = self._hash_resource_ref(address)

                skeleton.append(
                    ResourceChange(
                        resource_type=resource_type,
                        action=action,
                        changed_paths=changed_paths,
                        attribute_diffs=attribute_diffs,
                        resource_ref=resource_ref,
                        resource_address=address,
                    )
                )

            except Exception as e:
                logger.warning(f"Failed to process resource change: {e}")
                continue

        logger.info(f"Extracted {len(skeleton)} resource changes")
        return skeleton

    def _extract_attribute_diffs(
        self, before: dict[str, Any] | None, after: dict[str, Any] | None, prefix: str = ""
    ) -> list[AttributeDiff]:
        """
        Recursively extract changed attributes including before/after values.

        Args:
            before: Before state
            after: After state
            prefix: Path prefix for recursion

        Returns:
            List of AttributeDiff objects
        """
        diffs: list[AttributeDiff] = []

        # Handle None cases
        if before is None:
            before = {}
        if after is None:
            after = {}

        # Get all keys from both states
        all_keys = set(before.keys()) | set(after.keys())

        for key in all_keys:
            # Skip sensitive keys
            if key.lower() in self.sensitive_keys:
                continue

            full_path = f"{prefix}.{key}" if prefix else key

            before_val = before.get(key)
            after_val = after.get(key)

            # Check if values differ
            if before_val != after_val:
                # For nested dicts, recurse
                if isinstance(before_val, dict) and isinstance(after_val, dict):
                    nested_diffs = self._extract_attribute_diffs(before_val, after_val, full_path)
                    diffs.extend(nested_diffs)
                else:
                    # Primitive value or list changed
                    # Apply Aggressive Sanitization
                    is_safe = False

                    # Check if the leaf key or any part of the path is in allowlist
                    for segment in full_path.split("."):
                        if segment.lower() in self.safe_attributes:
                            is_safe = True
                            break

                    # Even if in allowlist, check for secrets in strings
                    sanitized_before = self._sanitize_value(before_val) if is_safe else "[REDACTED]"
                    sanitized_after = self._sanitize_value(after_val) if is_safe else "[REDACTED]"

                    diffs.append(AttributeDiff(path=full_path, before=sanitized_before, after=sanitized_after))

        # Sort by path for consistent results
        diffs.sort(key=lambda x: x.path)
        return diffs

    def _sanitize_value(self, value: Any) -> Any:
        """
        Scan string values for potential secrets and redact them.
        """
        if not isinstance(value, str):
            return value

        # Don't scan very short strings
        if len(value) < 8:
            return value

        for pattern in self.secret_patterns:
            if pattern.search(value):
                logger.warning("SECRET DETECTED: Regexp match found. Redacting value.")
                return "[SECRET-DETECTED]"

        return value

    def _hash_resource_ref(self, address: str) -> str:
        """
        Generate stable hash for resource address.

        Args:
            address: Terraform resource address (e.g., aws_security_group.example)

        Returns:
            Hashed reference (e.g., res_9f31a02c1b)
        """
        hash_obj = hashlib.sha256(address.encode("utf-8"))
        hash_hex = hash_obj.hexdigest()[:10]
        return f"res_{hash_hex}"

    def get_resource_by_address(self, plan_json: dict[str, Any], address: str) -> dict[str, Any] | None:
        """
        Retrieve full resource change data by address.

        Args:
            plan_json: Parsed plan JSON
            address: Resource address to find

        Returns:
            Resource change dict or None if not found
        """
        for change in plan_json.get("resource_changes", []):
            if change.get("address") == address:
                return change
        return None

    def calculate_plan_hash(
        self,
        diff_skeleton: list[ResourceChange],
        options: dict[str, Any] | None = None,
    ) -> str:
        """
        Calculate a stable SHA-256 fingerprint for the plan.

        This uses the sanitized diff skeleton (types, actions, and changed paths)
        AND any analysis options that affect the findings (e.g., FedRAMP checks).
        By sorting the skeleton by resource hash, we ensure identical plans
        produce identical fingerprints regardless of internal JSON ordering.

        Args:
            diff_skeleton: Minimal representation of plan changes
            options: Analysis options to include in the hash

        Returns:
            SHA-256 hash string
        """
        # Sort by resource_ref to ensure deterministic fingerprint
        sorted_skeleton = sorted(diff_skeleton, key=lambda x: x.resource_ref)

        # Serialize only the data that matters for the security vibe
        hashable_data = {
            "skeleton": [
                {
                    "type": c.resource_type,
                    "action": c.action,
                    "paths": sorted(c.changed_paths),
                    "diffs": [d.model_dump() for d in sorted(c.attribute_diffs, key=lambda x: x.path)],
                }
                for c in sorted_skeleton
            ],
            "options": {
                "fedramp_moderate": options.get("fedramp_moderate", False) if options else False,
                "fedramp_high": options.get("fedramp_high", False) if options else False,
            },
        }

        skeleton_json = json.dumps(hashable_data, sort_keys=True)
        return hashlib.sha256(skeleton_json.encode("utf-8")).hexdigest()
