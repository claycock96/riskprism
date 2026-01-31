"""
FedRAMP Compliance Service Mappings

AWS Services authorized under FedRAMP Moderate (East/West) and High (GovCloud).
Source: https://aws.amazon.com/compliance/services-in-scope/FedRAMP/
Last updated: December 4, 2025 (per AWS)

Services are mapped by their AWS service prefix (e.g., 'ec2', 's3', 'lambda').
"""

import logging
from enum import Enum

logger = logging.getLogger(__name__)


class FedRAMPLevel(Enum):
    MODERATE = "moderate"
    HIGH = "high"


# FedRAMP Moderate (East/West) - Full list of authorized service prefixes
# Based on AWS FedRAMP Services in Scope page
FEDRAMP_MODERATE_SERVICES: set[str] = {
    # Compute
    "ec2",
    "lambda",
    "elasticbeanstalk",
    "batch",
    "lightsail",
    "outposts",
    "imagebuilder",
    # Containers
    "ecs",
    "ecr",
    "eks",
    "fargate",
    # Storage
    "s3",
    "ebs",
    "efs",
    "fsx",
    "glacier",
    "storagegateway",
    "backup",
    "datasync",
    "snowball",
    # Database
    "rds",
    "aurora",
    "dynamodb",
    "elasticache",
    "documentdb",
    "neptune",
    "redshift",
    "keyspaces",
    "memorydb",
    "timestream",
    "dms",
    # Networking
    "vpc",
    "cloudfront",
    "route53",
    "apigateway",
    "directconnect",
    "globalaccelerator",
    "elb",
    "elasticloadbalancing",
    "appmesh",
    "cloudmap",
    "networkfirewall",
    "transitgateway",
    # Security & Identity
    "iam",
    "kms",
    "secretsmanager",
    "acm",
    "cloudhsm",
    "waf",
    "wafv2",
    "shield",
    "guardduty",
    "inspector",
    "macie",
    "detective",
    "securityhub",
    "sso",
    "identitystore",
    "sts",
    "organizations",
    "ram",
    "signer",
    "verifiedaccess",
    "acm-pca",
    "privateca",
    "artifact",
    "auditmanager",
    # Management & Governance
    "cloudformation",
    "cloudwatch",
    "logs",
    "events",
    "cloudtrail",
    "config",
    "ssm",
    "systems-manager",
    "servicecatalog",
    "controltower",
    "health",
    "trustedadvisor",
    "wellarchitected",
    "resourcegroups",
    "tag",
    "licensemanager",
    "compute-optimizer",
    "servicequotas",
    "fis",
    "resiliencehub",
    # Developer Tools
    "codebuild",
    "codecommit",
    "codedeploy",
    "codepipeline",
    "cloud9",
    "cloudshell",
    "xray",
    # Analytics
    "athena",
    "emr",
    "kinesis",
    "firehose",
    "glue",
    "databrew",
    "lakeformation",
    "opensearch",
    "es",
    "quicksight",
    "msk",
    "kafka",
    "dataexchange",
    "finspace",
    # Machine Learning
    "sagemaker",
    "comprehend",
    "rekognition",
    "textract",
    "transcribe",
    "translate",
    "polly",
    "lex",
    "kendra",
    "forecast",
    "bedrock",
    "personalize",
    "devops-guru",
    "lookoutvision",
    "lookoutmetrics",
    "lookoutequipment",
    "healthlake",
    "healthimaging",
    "healthomics",
    # Application Integration
    "sns",
    "sqs",
    "stepfunctions",
    "states",
    "eventbridge",
    "mq",
    "swf",
    "appflow",
    # Business Applications
    "ses",
    "pinpoint",
    "connect",
    "chime",
    "workspaces",
    "appstream",
    "workdocs",
    "workmail",
    "wickr",
    # IoT
    "iot",
    "greengrass",
    "iot-device-defender",
    "iot-device-management",
    "iotevents",
    "iotsitewise",
    "iottwinmaker",
    # Other
    "cognito",
    "directory",
    "ds",
    "marketplace",
    "transfer",
    "mgn",
    "drs",
    "mainframe-modernization",
    "mediaconvert",
    "entity-resolution",
    "cleanrooms",
    "datazone",
    "prometheus",
    "grafana",
    "groundstation",
    "location",
    "verified-permissions",
    "q",  # Amazon Q
    "budgets",
    "billing",
    "ce",  # Cost Explorer
    "cur",  # Cost and Usage Reports
    "billingconductor",
}

# FedRAMP High (GovCloud) - Subset authorized for High impact
# Generally same services available in GovCloud regions
FEDRAMP_HIGH_SERVICES: set[str] = {
    # Core compute
    "ec2",
    "lambda",
    "elasticbeanstalk",
    "batch",
    "imagebuilder",
    # Containers
    "ecs",
    "ecr",
    "eks",
    "fargate",
    # Storage
    "s3",
    "ebs",
    "efs",
    "fsx",
    "glacier",
    "storagegateway",
    "backup",
    "datasync",
    "snowball",
    # Database
    "rds",
    "aurora",
    "dynamodb",
    "elasticache",
    "documentdb",
    "neptune",
    "redshift",
    "keyspaces",
    "memorydb",
    "dms",
    # Networking
    "vpc",
    "apigateway",
    "directconnect",
    "elb",
    "elasticloadbalancing",
    "appmesh",
    "cloudmap",
    "networkfirewall",
    "transitgateway",
    # Security & Identity
    "iam",
    "kms",
    "secretsmanager",
    "acm",
    "cloudhsm",
    "waf",
    "wafv2",
    "shield",
    "guardduty",
    "inspector",
    "macie",
    "detective",
    "securityhub",
    "sso",
    "identitystore",
    "sts",
    "organizations",
    "ram",
    "signer",
    "acm-pca",
    "privateca",
    "artifact",
    "auditmanager",
    # Management & Governance
    "cloudformation",
    "cloudwatch",
    "logs",
    "events",
    "cloudtrail",
    "config",
    "ssm",
    "systems-manager",
    "servicecatalog",
    "controltower",
    "health",
    "trustedadvisor",
    "wellarchitected",
    "resourcegroups",
    "tag",
    "licensemanager",
    "compute-optimizer",
    "servicequotas",
    "resiliencehub",
    # Developer Tools
    "codebuild",
    "codecommit",
    "codedeploy",
    "codepipeline",
    "cloud9",
    "cloudshell",
    "xray",
    # Analytics
    "athena",
    "emr",
    "kinesis",
    "firehose",
    "glue",
    "databrew",
    "lakeformation",
    "opensearch",
    "es",
    "quicksight",
    "msk",
    "kafka",
    # Machine Learning
    "sagemaker",
    "comprehend",
    "rekognition",
    "textract",
    "transcribe",
    "translate",
    "polly",
    "lex",
    "kendra",
    "bedrock",
    # Application Integration
    "sns",
    "sqs",
    "stepfunctions",
    "states",
    "eventbridge",
    "mq",
    "swf",
    "appflow",
    # Business Applications
    "workspaces",
    "appstream",
    # IoT
    "iot",
    "greengrass",
    "iot-device-defender",
    "iot-device-management",
    "iotevents",
    "iotsitewise",
    # Other
    "cognito",
    "directory",
    "ds",
    "marketplace",
    "transfer",
    "mgn",
    "drs",
    "prometheus",
    "grafana",
    "location",
}


def get_service_from_resource_type(resource_type: str) -> str | None:
    """
    Extract AWS service prefix from Terraform resource type.

    Examples:
        aws_s3_bucket -> s3
        aws_lambda_function -> lambda
        aws_iam_role -> iam
        aws_rds_cluster -> rds

    Args:
        resource_type: Terraform resource type (e.g., 'aws_s3_bucket')

    Returns:
        Service prefix or None if not an AWS resource
    """
    if not resource_type or not resource_type.startswith("aws_"):
        return None

    # Remove 'aws_' prefix
    without_prefix = resource_type[4:]

    # Common multi-word service mappings
    service_mappings = {
        "api_gateway": "apigateway",
        "apigatewayv2": "apigateway",
        "cloudwatch_log": "logs",
        "cloudwatch_event": "events",
        "elastic_beanstalk": "elasticbeanstalk",
        "elasticache": "elasticache",
        "elasticsearch": "es",
        "opensearch": "opensearch",
        "load_balancer": "elb",
        "lb": "elb",
        "alb": "elb",
        "nlb": "elb",
        "security_group": "ec2",
        "network_interface": "ec2",
        "eip": "ec2",
        "key_pair": "ec2",
        "placement_group": "ec2",
        "db_instance": "rds",
        "db_cluster": "rds",
        "db_subnet_group": "rds",
        "db_parameter_group": "rds",
        "db_security_group": "rds",
        "sfn": "stepfunctions",
        "cloud_formation": "cloudformation",
        "acm_certificate": "acm",
        "acmpca": "acm-pca",
        "ssm_parameter": "ssm",
        "ssm_document": "ssm",
        "ssm_maintenance": "ssm",
        "ssm_patch": "ssm",
        "ssm_association": "ssm",
        "secretsmanager": "secretsmanager",  # pragma: allowlist secret
        "kms_key": "kms",
        "kms_alias": "kms",
        "kms_grant": "kms",
        "transfer_server": "transfer",
        "transfer_user": "transfer",
    }

    # Check for known multi-word mappings first
    for pattern, service in service_mappings.items():
        if without_prefix.startswith(pattern):
            return service

    # Default: take first segment before underscore
    parts = without_prefix.split("_")
    return parts[0] if parts else None


def get_service_from_action(action: str) -> str | None:
    """
    Extract AWS service prefix from IAM action.

    Examples:
        s3:GetObject -> s3
        lambda:InvokeFunction -> lambda
        iam:CreateRole -> iam

    Args:
        action: IAM action (e.g., 's3:GetObject')

    Returns:
        Service prefix or None if invalid format
    """
    if not action or ":" not in action:
        return None

    # Handle wildcards
    if action == "*":
        return None  # Wildcard means all services

    service = action.split(":")[0].lower()
    return service if service else None


def check_fedramp_compliance(service: str, level: FedRAMPLevel) -> tuple[bool, str | None]:
    """
    Check if a service is authorized for the specified FedRAMP level.

    Args:
        service: AWS service prefix (e.g., 's3', 'lambda')
        level: FedRAMP authorization level to check

    Returns:
        Tuple of (is_compliant, message)
    """
    if not service:
        return True, None  # Can't determine, assume OK

    service_lower = service.lower()

    if level == FedRAMPLevel.MODERATE:
        if service_lower in FEDRAMP_MODERATE_SERVICES:
            return True, None
        return False, f"Service '{service}' is not FedRAMP Moderate authorized"

    elif level == FedRAMPLevel.HIGH:
        if service_lower in FEDRAMP_HIGH_SERVICES:
            return True, None
        return False, f"Service '{service}' is not FedRAMP High (GovCloud) authorized"

    return True, None


def get_non_compliant_services(services: list[str], level: FedRAMPLevel) -> list[str]:
    """
    Filter a list of services to return only non-compliant ones.

    Args:
        services: List of service prefixes
        level: FedRAMP authorization level to check

    Returns:
        List of non-compliant service prefixes
    """
    non_compliant = []
    service_set = FEDRAMP_MODERATE_SERVICES if level == FedRAMPLevel.MODERATE else FEDRAMP_HIGH_SERVICES

    for service in services:
        if service and service.lower() not in service_set:
            non_compliant.append(service)

    return non_compliant
