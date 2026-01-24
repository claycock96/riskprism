import hashlib
import json
from typing import Dict, Any, List, Set, Optional
import logging

from app.models import PlanSummary, ResourceChange

logger = logging.getLogger(__name__)


class TerraformPlanParser:
    """
    Parses Terraform plan JSON and extracts minimal diff skeleton.

    Key responsibilities:
    - Validate plan JSON structure
    - Extract resource changes
    - Compute changed attribute paths
    - Generate stable hashes for resource references
    - Never expose sensitive values
    """

    def __init__(self):
        self.sensitive_keys = {
            'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
            'access_key', 'secret_key', 'private_key', 'client_secret',
            'certificate', 'cert', 'key_material', 'user_data', 'bootstrap'
        }

    def parse(self, plan_json: Dict[str, Any]) -> Dict[str, Any]:
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
        if 'resource_changes' not in plan_json:
            raise ValueError("Missing 'resource_changes' field in plan JSON")

        logger.info(f"Parsed plan with {len(plan_json.get('resource_changes', []))} resource changes")
        return plan_json

    def generate_summary(self, plan_json: Dict[str, Any]) -> PlanSummary:
        """
        Generate high-level summary statistics from plan.

        Args:
            plan_json: Parsed plan JSON

        Returns:
            PlanSummary with counts and metadata
        """
        resource_changes = plan_json.get('resource_changes', [])

        creates = 0
        updates = 0
        deletes = 0
        replaces = 0

        for change in resource_changes:
            actions = change.get('change', {}).get('actions', [])

            if 'create' in actions and 'delete' in actions:
                replaces += 1
            elif 'create' in actions:
                creates += 1
            elif 'update' in actions:
                updates += 1
            elif 'delete' in actions:
                deletes += 1

        terraform_version = plan_json.get('terraform_version')

        return PlanSummary(
            total_changes=creates + updates + deletes + replaces,
            creates=creates,
            updates=updates,
            deletes=deletes,
            replaces=replaces,
            terraform_version=terraform_version
        )

    def extract_diff_skeleton(self, plan_json: Dict[str, Any]) -> List[ResourceChange]:
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
        resource_changes = plan_json.get('resource_changes', [])
        skeleton = []

        for change in resource_changes:
            try:
                resource_type = change.get('type', 'unknown')
                address = change.get('address', 'unknown')
                change_data = change.get('change', {})
                actions = change_data.get('actions', [])

                # Determine primary action
                if 'create' in actions and 'delete' in actions:
                    action = 'replace'
                elif 'create' in actions:
                    action = 'create'
                elif 'update' in actions:
                    action = 'update'
                elif 'delete' in actions:
                    action = 'delete'
                elif 'no-op' in actions:
                    continue  # Skip no-op changes
                else:
                    action = 'unknown'

                # Extract changed paths
                before = change_data.get('before', {})
                after = change_data.get('after', {})
                changed_paths = self._extract_changed_paths(before, after)

                # Generate stable hash for resource reference
                resource_id_hash = self._hash_resource_ref(address)

                skeleton.append(ResourceChange(
                    resource_type=resource_type,
                    action=action,
                    changed_paths=changed_paths,
                    resource_id_hash=resource_id_hash,
                    resource_address=address
                ))

            except Exception as e:
                logger.warning(f"Failed to process resource change: {e}")
                continue

        logger.info(f"Extracted {len(skeleton)} resource changes")
        return skeleton

    def _extract_changed_paths(
        self,
        before: Optional[Dict[str, Any]],
        after: Optional[Dict[str, Any]],
        prefix: str = ""
    ) -> List[str]:
        """
        Recursively extract paths of changed attributes.

        Returns only attribute key paths, not values.

        Args:
            before: Before state
            after: After state
            prefix: Path prefix for recursion

        Returns:
            List of changed attribute paths (e.g., ['ingress', 'egress.cidr_blocks'])
        """
        changed_paths: Set[str] = set()

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
                    nested_paths = self._extract_changed_paths(before_val, after_val, full_path)
                    changed_paths.update(nested_paths)
                # For lists, just record the container key
                elif isinstance(before_val, list) or isinstance(after_val, list):
                    changed_paths.add(full_path)
                else:
                    # Primitive value changed
                    changed_paths.add(full_path)

        return sorted(list(changed_paths))

    def _hash_resource_ref(self, address: str) -> str:
        """
        Generate stable hash for resource address.

        Args:
            address: Terraform resource address (e.g., aws_security_group.example)

        Returns:
            Hashed reference (e.g., res_9f31a02c1b)
        """
        hash_obj = hashlib.sha256(address.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()[:10]
        return f"res_{hash_hex}"

    def get_resource_by_address(
        self,
        plan_json: Dict[str, Any],
        address: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve full resource change data by address.

        Args:
            plan_json: Parsed plan JSON
            address: Resource address to find

        Returns:
            Resource change dict or None if not found
        """
        for change in plan_json.get('resource_changes', []):
            if change.get('address') == address:
                return change
        return None
