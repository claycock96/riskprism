import hashlib
import json
from typing import Dict, Any, List, Set, Optional
import logging

from app.models import PlanSummary, ResourceChange, AttributeDiff

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

                # Extract changed paths and diffs
                before = change_data.get('before', {})
                after = change_data.get('after', {})
                attribute_diffs = self._extract_attribute_diffs(before, after)
                changed_paths = [d.path for d in attribute_diffs]

                # Generate stable hash for resource reference
                resource_id_hash = self._hash_resource_ref(address)

                skeleton.append(ResourceChange(
                    resource_type=resource_type,
                    action=action,
                    changed_paths=changed_paths,
                    attribute_diffs=attribute_diffs,
                    resource_id_hash=resource_id_hash,
                    resource_address=address
                ))

            except Exception as e:
                logger.warning(f"Failed to process resource change: {e}")
                continue

        logger.info(f"Extracted {len(skeleton)} resource changes")
        return skeleton

    def _extract_attribute_diffs(
        self,
        before: Optional[Dict[str, Any]],
        after: Optional[Dict[str, Any]],
        prefix: str = ""
    ) -> List[AttributeDiff]:
        """
        Recursively extract changed attributes including before/after values.

        Args:
            before: Before state
            after: After state
            prefix: Path prefix for recursion

        Returns:
            List of AttributeDiff objects
        """
        diffs: List[AttributeDiff] = []

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
                    # For lists, we currently record the whole container if it changed
                    diffs.append(AttributeDiff(
                        path=full_path,
                        before=before_val,
                        after=after_val
                    ))

        # Sort by path for consistent results
        diffs.sort(key=lambda x: x.path)
        return diffs

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

    def calculate_plan_hash(self, diff_skeleton: List[ResourceChange]) -> str:
        """
        Calculate a stable SHA-256 fingerprint for the plan.
        
        This uses the sanitized diff skeleton (types, actions, and changed paths).
        By sorting the skeleton by resource hash, we ensure identical plans
        produce identical fingerprints regardless of internal JSON ordering.
        
        Args:
            diff_skeleton: Minimal representation of plan changes
            
        Returns:
            SHA-256 hash string
        """
        # Sort by resource_id_hash to ensure deterministic fingerprint
        sorted_skeleton = sorted(diff_skeleton, key=lambda x: x.resource_id_hash)
        
        # Serialize only the data that matters for the security vibe
        hashable_data = [
            {
                "type": c.resource_type,
                "action": c.action,
                "paths": sorted(c.changed_paths)
            }
            for c in sorted_skeleton
        ]
        
        skeleton_json = json.dumps(hashable_data, sort_keys=True)
        return hashlib.sha256(skeleton_json.encode('utf-8')).hexdigest()
