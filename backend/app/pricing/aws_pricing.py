"""
AWS Pricing Database.

Static pricing data for common AWS resource types.
Pricing baseline: us-gov-west-1 (AWS GovCloud West)

Note: GovCloud pricing is generally higher than commercial regions.
This module provides baseline estimates; actual costs may vary based on:
- Reserved instances / Savings Plans
- Data transfer
- Request volumes
- Storage tiers and access patterns

Last Updated: 2026-01-30
"""

from typing import Any

# Pricing data last updated date (ISO format)
PRICING_LAST_UPDATED = "2026-01-30"
PRICING_REGION = "us-gov-west-1"

# =============================================================================
# EC2 Instance Pricing (On-Demand, Linux, per hour)
# GovCloud pricing is approximately 10-20% higher than commercial regions
# =============================================================================

EC2_INSTANCE_PRICING: dict[str, float] = {
    # General Purpose - T3
    "t3.nano": 0.0063,
    "t3.micro": 0.0125,
    "t3.small": 0.0250,
    "t3.medium": 0.0500,
    "t3.large": 0.0999,
    "t3.xlarge": 0.1998,
    "t3.2xlarge": 0.3996,
    # General Purpose - T3a
    "t3a.nano": 0.0056,
    "t3a.micro": 0.0113,
    "t3a.small": 0.0226,
    "t3a.medium": 0.0451,
    "t3a.large": 0.0902,
    "t3a.xlarge": 0.1805,
    "t3a.2xlarge": 0.3610,
    # General Purpose - M5
    "m5.large": 0.115,
    "m5.xlarge": 0.230,
    "m5.2xlarge": 0.460,
    "m5.4xlarge": 0.920,
    "m5.8xlarge": 1.840,
    "m5.12xlarge": 2.760,
    "m5.16xlarge": 3.680,
    "m5.24xlarge": 5.520,
    # General Purpose - M6i
    "m6i.large": 0.115,
    "m6i.xlarge": 0.230,
    "m6i.2xlarge": 0.460,
    "m6i.4xlarge": 0.920,
    # Compute Optimized - C5
    "c5.large": 0.102,
    "c5.xlarge": 0.204,
    "c5.2xlarge": 0.408,
    "c5.4xlarge": 0.816,
    "c5.9xlarge": 1.836,
    "c5.18xlarge": 3.672,
    # Memory Optimized - R5
    "r5.large": 0.151,
    "r5.xlarge": 0.302,
    "r5.2xlarge": 0.604,
    "r5.4xlarge": 1.208,
    "r5.8xlarge": 2.416,
    "r5.12xlarge": 3.624,
    # Graviton (ARM) - T4g
    "t4g.nano": 0.0050,
    "t4g.micro": 0.0100,
    "t4g.small": 0.0200,
    "t4g.medium": 0.0400,
    "t4g.large": 0.0800,
    "t4g.xlarge": 0.1600,
    "t4g.2xlarge": 0.3200,
    # Graviton - M6g
    "m6g.medium": 0.0578,
    "m6g.large": 0.1155,
    "m6g.xlarge": 0.2310,
    "m6g.2xlarge": 0.4620,
}

# Default instance type if not specified
DEFAULT_INSTANCE_TYPE = "t3.medium"
DEFAULT_INSTANCE_HOURLY = EC2_INSTANCE_PRICING.get(DEFAULT_INSTANCE_TYPE, 0.0500)

# =============================================================================
# RDS Instance Pricing (On-Demand, per hour)
# =============================================================================

RDS_INSTANCE_PRICING: dict[str, float] = {
    # MySQL / PostgreSQL
    "db.t3.micro": 0.021,
    "db.t3.small": 0.042,
    "db.t3.medium": 0.084,
    "db.t3.large": 0.168,
    "db.t3.xlarge": 0.336,
    "db.t3.2xlarge": 0.672,
    # M5 Series
    "db.m5.large": 0.195,
    "db.m5.xlarge": 0.390,
    "db.m5.2xlarge": 0.780,
    "db.m5.4xlarge": 1.560,
    "db.m5.8xlarge": 3.120,
    # R5 Series (Memory Optimized)
    "db.r5.large": 0.290,
    "db.r5.xlarge": 0.580,
    "db.r5.2xlarge": 1.160,
    "db.r5.4xlarge": 2.320,
    # Graviton
    "db.t4g.micro": 0.019,
    "db.t4g.small": 0.038,
    "db.t4g.medium": 0.076,
    "db.m6g.large": 0.175,
    "db.m6g.xlarge": 0.350,
}

DEFAULT_RDS_INSTANCE_CLASS = "db.t3.medium"
DEFAULT_RDS_HOURLY = RDS_INSTANCE_PRICING.get(DEFAULT_RDS_INSTANCE_CLASS, 0.084)

# =============================================================================
# EBS Volume Pricing (per GB-month)
# =============================================================================

EBS_VOLUME_PRICING: dict[str, float] = {
    "gp2": 0.12,  # General Purpose SSD (legacy)
    "gp3": 0.096,  # General Purpose SSD v3
    "io1": 0.145,  # Provisioned IOPS SSD
    "io2": 0.145,  # Provisioned IOPS SSD v2
    "st1": 0.054,  # Throughput Optimized HDD
    "sc1": 0.030,  # Cold HDD
    "standard": 0.055,  # Magnetic
}

DEFAULT_EBS_TYPE = "gp3"
DEFAULT_EBS_SIZE_GB = 20
DEFAULT_EBS_PER_GB = EBS_VOLUME_PRICING.get(DEFAULT_EBS_TYPE, 0.096)

# =============================================================================
# S3 Storage Pricing (per GB-month, Standard tier)
# =============================================================================

S3_PRICING = {
    "storage_per_gb": 0.028,  # Standard storage
    "requests_put_per_1k": 0.0055,
    "requests_get_per_1k": 0.00044,
    "data_transfer_per_gb": 0.09,  # Outbound to internet
}

# =============================================================================
# Lambda Pricing
# =============================================================================

LAMBDA_PRICING = {
    "requests_per_million": 0.20,
    "duration_per_gb_second": 0.0000166667,
    "provisioned_concurrency_per_gb_hour": 0.015,
}

# =============================================================================
# NAT Gateway Pricing
# =============================================================================

NAT_GATEWAY_PRICING = {
    "hourly": 0.054,
    "data_per_gb": 0.054,
}

# =============================================================================
# Load Balancer Pricing
# =============================================================================

LOAD_BALANCER_PRICING = {
    "alb_hourly": 0.027,
    "alb_lcu_hourly": 0.0084,
    "nlb_hourly": 0.027,
    "nlb_lcu_hourly": 0.0072,
    "clb_hourly": 0.030,
    "clb_data_per_gb": 0.008,
}

# =============================================================================
# EKS Pricing
# =============================================================================

EKS_PRICING = {
    "cluster_hourly": 0.10,
}

# =============================================================================
# ElastiCache Pricing
# =============================================================================

ELASTICACHE_PRICING: dict[str, float] = {
    "cache.t3.micro": 0.021,
    "cache.t3.small": 0.042,
    "cache.t3.medium": 0.084,
    "cache.m5.large": 0.195,
    "cache.m5.xlarge": 0.390,
    "cache.r5.large": 0.290,
    "cache.r5.xlarge": 0.580,
}

# =============================================================================
# Other Fixed-Cost Resources
# =============================================================================

FIXED_HOURLY_COSTS: dict[str, float] = {
    "aws_nat_gateway": NAT_GATEWAY_PRICING["hourly"],
    "aws_lb": LOAD_BALANCER_PRICING["alb_hourly"],
    "aws_alb": LOAD_BALANCER_PRICING["alb_hourly"],
    "aws_elb": LOAD_BALANCER_PRICING["clb_hourly"],
    "aws_eks_cluster": EKS_PRICING["cluster_hourly"],
    "aws_vpn_gateway": 0.05,
    "aws_customer_gateway": 0.0,  # No charge
    "aws_vpc_endpoint": 0.013,  # Interface endpoint per AZ-hour
    "aws_elasticsearch_domain": 0.092,  # t3.small.search baseline
    "aws_opensearch_domain": 0.092,
}

# =============================================================================
# Resources with no direct cost (free tier / included)
# =============================================================================

FREE_RESOURCES: set[str] = {
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_user",
    "aws_iam_group",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy",
    "aws_iam_group_policy_attachment",
    "aws_iam_instance_profile",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc",
    "aws_subnet",
    "aws_route_table",
    "aws_route_table_association",
    "aws_route",
    "aws_internet_gateway",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_cloudwatch_log_group",  # Pay for data ingested, not the group itself
    "aws_sns_topic",  # Pay per message
    "aws_sqs_queue",  # Pay per request
    "aws_kms_key",  # $1/month per key, minimal
    "aws_kms_alias",
    "aws_ssm_parameter",  # Free for standard tier
}

# Hours per month for cost calculation
HOURS_PER_MONTH = 730


def get_ec2_hourly_cost(instance_type: str | None) -> tuple[float, str]:
    """
    Get EC2 hourly cost for an instance type.

    Returns:
        Tuple of (hourly_cost, confidence)
    """
    if not instance_type:
        return DEFAULT_INSTANCE_HOURLY, "medium"

    instance_type = instance_type.lower()
    if instance_type in EC2_INSTANCE_PRICING:
        return EC2_INSTANCE_PRICING[instance_type], "high"

    # Try to find a similar instance type
    family = instance_type.split(".")[0] if "." in instance_type else None
    if family:
        for known_type, price in EC2_INSTANCE_PRICING.items():
            if known_type.startswith(family):
                return price, "medium"

    return DEFAULT_INSTANCE_HOURLY, "low"


def get_rds_hourly_cost(instance_class: str | None) -> tuple[float, str]:
    """
    Get RDS hourly cost for an instance class.

    Returns:
        Tuple of (hourly_cost, confidence)
    """
    if not instance_class:
        return DEFAULT_RDS_HOURLY, "medium"

    instance_class = instance_class.lower()
    if instance_class in RDS_INSTANCE_PRICING:
        return RDS_INSTANCE_PRICING[instance_class], "high"

    return DEFAULT_RDS_HOURLY, "low"


def get_ebs_monthly_cost(volume_type: str | None, size_gb: int | None) -> tuple[float, str]:
    """
    Get EBS monthly cost for a volume.

    Returns:
        Tuple of (monthly_cost, confidence)
    """
    vol_type = (volume_type or DEFAULT_EBS_TYPE).lower()
    size = size_gb or DEFAULT_EBS_SIZE_GB

    per_gb_cost = EBS_VOLUME_PRICING.get(vol_type, DEFAULT_EBS_PER_GB)
    confidence = "high" if vol_type in EBS_VOLUME_PRICING else "medium"

    return per_gb_cost * size, confidence


def get_elasticache_hourly_cost(node_type: str | None) -> tuple[float, str]:
    """
    Get ElastiCache hourly cost for a node type.

    Returns:
        Tuple of (hourly_cost, confidence)
    """
    if not node_type:
        return 0.084, "medium"  # cache.t3.medium default

    node_type = node_type.lower()
    if node_type in ELASTICACHE_PRICING:
        return ELASTICACHE_PRICING[node_type], "high"

    return 0.084, "low"


def is_free_resource(resource_type: str) -> bool:
    """Check if a resource type has no direct cost."""
    return resource_type in FREE_RESOURCES


def get_fixed_hourly_cost(resource_type: str) -> float | None:
    """Get fixed hourly cost for a resource type, if known."""
    return FIXED_HOURLY_COSTS.get(resource_type)


def get_resource_pricing_info(resource_type: str, attributes: dict[str, Any]) -> dict[str, Any]:
    """
    Get pricing information for a resource based on its type and attributes.

    Args:
        resource_type: AWS resource type (e.g., "aws_instance")
        attributes: Resource attributes from the Terraform plan

    Returns:
        Dict with keys: monthly_cost, hourly_cost, confidence, pricing_unit, notes
    """
    # Free resources
    if is_free_resource(resource_type):
        return {
            "monthly_cost": 0.0,
            "hourly_cost": 0.0,
            "confidence": "high",
            "pricing_unit": "free",
            "notes": "No direct cost for this resource type",
        }

    # EC2 Instances
    if resource_type in ("aws_instance", "aws_spot_instance_request"):
        instance_type = attributes.get("instance_type")
        hourly, confidence = get_ec2_hourly_cost(instance_type)
        return {
            "monthly_cost": hourly * HOURS_PER_MONTH,
            "hourly_cost": hourly,
            "confidence": confidence,
            "pricing_unit": "per hour",
            "notes": f"Instance type: {instance_type or 'assumed ' + DEFAULT_INSTANCE_TYPE}",
        }

    # RDS Instances
    if resource_type == "aws_db_instance":
        instance_class = attributes.get("instance_class")
        hourly, confidence = get_rds_hourly_cost(instance_class)
        # Add storage cost estimate
        storage_gb = attributes.get("allocated_storage", 20)
        storage_cost = storage_gb * 0.125  # gp2 baseline
        return {
            "monthly_cost": (hourly * HOURS_PER_MONTH) + storage_cost,
            "hourly_cost": hourly,
            "confidence": confidence,
            "pricing_unit": "per hour + storage",
            "notes": f"Instance: {instance_class or 'assumed ' + DEFAULT_RDS_INSTANCE_CLASS}, Storage: {storage_gb}GB",
        }

    # EBS Volumes
    if resource_type == "aws_ebs_volume":
        volume_type = attributes.get("type", DEFAULT_EBS_TYPE)
        size_gb = attributes.get("size", DEFAULT_EBS_SIZE_GB)
        monthly, confidence = get_ebs_monthly_cost(volume_type, size_gb)
        return {
            "monthly_cost": monthly,
            "hourly_cost": None,
            "confidence": confidence,
            "pricing_unit": "per GB-month",
            "notes": f"{volume_type}: {size_gb}GB",
        }

    # S3 Buckets (estimate based on typical usage)
    if resource_type == "aws_s3_bucket":
        # Assume 10GB baseline storage
        estimated_storage_gb = 10
        return {
            "monthly_cost": S3_PRICING["storage_per_gb"] * estimated_storage_gb,
            "hourly_cost": None,
            "confidence": "low",
            "pricing_unit": "per GB-month",
            "notes": f"Estimated {estimated_storage_gb}GB storage (actual varies by usage)",
        }

    # Lambda Functions
    if resource_type == "aws_lambda_function":
        memory_mb = attributes.get("memory_size", 128)
        # Assume 1M requests/month with 200ms avg duration
        estimated_requests = 1_000_000
        estimated_duration_ms = 200
        gb_seconds = (memory_mb / 1024) * (estimated_duration_ms / 1000) * estimated_requests
        duration_cost = gb_seconds * LAMBDA_PRICING["duration_per_gb_second"]
        request_cost = (estimated_requests / 1_000_000) * LAMBDA_PRICING["requests_per_million"]
        return {
            "monthly_cost": duration_cost + request_cost,
            "hourly_cost": None,
            "confidence": "low",
            "pricing_unit": "per request + duration",
            "notes": f"Estimate: 1M requests/month, {memory_mb}MB memory",
        }

    # NAT Gateway
    if resource_type == "aws_nat_gateway":
        # Assume 100GB/month data processing
        estimated_data_gb = 100
        hourly_cost = NAT_GATEWAY_PRICING["hourly"]
        data_cost = estimated_data_gb * NAT_GATEWAY_PRICING["data_per_gb"]
        return {
            "monthly_cost": (hourly_cost * HOURS_PER_MONTH) + data_cost,
            "hourly_cost": hourly_cost,
            "confidence": "medium",
            "pricing_unit": "per hour + data",
            "notes": f"Estimate: {estimated_data_gb}GB data processed",
        }

    # Load Balancers
    if resource_type in ("aws_lb", "aws_alb"):
        hourly_cost = LOAD_BALANCER_PRICING["alb_hourly"]
        # Assume 10 LCU average
        lcu_cost = 10 * LOAD_BALANCER_PRICING["alb_lcu_hourly"] * HOURS_PER_MONTH
        return {
            "monthly_cost": (hourly_cost * HOURS_PER_MONTH) + lcu_cost,
            "hourly_cost": hourly_cost,
            "confidence": "medium",
            "pricing_unit": "per hour + LCU",
            "notes": "Estimate: 10 LCU average",
        }

    # EKS Cluster
    if resource_type == "aws_eks_cluster":
        hourly_cost = EKS_PRICING["cluster_hourly"]
        return {
            "monthly_cost": hourly_cost * HOURS_PER_MONTH,
            "hourly_cost": hourly_cost,
            "confidence": "high",
            "pricing_unit": "per hour",
            "notes": "Cluster control plane only (worker nodes billed separately)",
        }

    # ElastiCache
    if resource_type in ("aws_elasticache_cluster", "aws_elasticache_replication_group"):
        node_type = attributes.get("node_type")
        num_nodes = attributes.get("num_cache_nodes", 1)
        hourly, confidence = get_elasticache_hourly_cost(node_type)
        return {
            "monthly_cost": hourly * HOURS_PER_MONTH * num_nodes,
            "hourly_cost": hourly,
            "confidence": confidence,
            "pricing_unit": "per node-hour",
            "notes": f"{num_nodes}x {node_type or 'cache.t3.medium'}",
        }

    # Fixed hourly cost resources
    fixed_hourly = get_fixed_hourly_cost(resource_type)
    if fixed_hourly is not None:
        return {
            "monthly_cost": fixed_hourly * HOURS_PER_MONTH,
            "hourly_cost": fixed_hourly,
            "confidence": "medium",
            "pricing_unit": "per hour",
            "notes": None,
        }

    # Unknown resource - return None to signal LLM fallback
    return None
