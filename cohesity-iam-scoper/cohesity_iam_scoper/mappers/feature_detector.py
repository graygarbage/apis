"""Feature detector - maps customer configuration selections to IAM permissions."""

from typing import Any, Optional

from cohesity_iam_scoper.mappers.permission_map import PermissionMapper


FEATURE_DISPLAY_NAMES = {
    "source_registration_aws": "AWS Source Registration",
    "ec2_vm_backup": "EC2 VM Backup",
    "ebs_direct_api": "EBS Direct API (Block-Level Backup)",
    "ec2_vm_restore": "EC2 VM Restore / CloudSpin",
    "rds_backup": "RDS Backup",
    "rds_restore": "RDS Restore",
    "rds_db_connect": "RDS DB Connect (IAM Auth)",
    "rds_staging_s3": "RDS Backup S3 Staging",
    "redshift_backup": "Redshift Backup",
    "dynamodb_backup": "DynamoDB Backup",
    "s3_protection": "S3 Protection (S3 as Source)",
    "s3_archive": "S3 Archive (External Target)",
    "glacier_archive": "Glacier Archive",
    "iam_role_management": "IAM Role Management",
    "instance_role": "Cohesity Instance Role",
    "ssm_operations": "SSM Operations (App-Consistent Backups)",
    "cloudformation_management": "CloudFormation Stack Management",
    "kms_encryption": "KMS Encryption",
}


class FeatureDetector:
    """Resolves a customer configuration into a concrete set of IAM permissions."""

    def __init__(self, mapper: Optional[PermissionMapper] = None) -> None:
        self._mapper = mapper or PermissionMapper()

    def resolve_permissions(
        self, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Resolve a customer configuration into grouped IAM permission data.

        Args:
            config: Configuration dict (from configure/init command output).

        Returns:
            A dict with:
              - selected_features: list of feature keys selected
              - permissions_by_service: permissions grouped by AWS service prefix
              - resource_scoping: per-action resource scoping rules
              - total_count: total unique permissions
        """
        selected = config.get("selected_features", [])
        if not selected:
            selected = self._mapper.feature_keys

        s3_config = config.get("s3", {})
        ec2_config = config.get("ec2", {})
        rds_config = config.get("rds", {})
        iam_config = config.get("iam", {})
        aws_config = config.get("aws", {})

        all_permissions: list[str] = []
        resource_scoping: dict[str, Any] = {}
        seen: set[str] = set()

        for feature_key in selected:
            if feature_key not in self._mapper.feature_keys:
                continue
            perms = self._mapper.get_required_permissions(feature_key)
            for p in perms:
                if p not in seen:
                    seen.add(p)
                    all_permissions.append(p)

            scoping = self._mapper.get_resource_scoping(feature_key)
            for action, rule in scoping.items():
                if action not in resource_scoping:
                    resource_scoping[action] = dict(rule)
                    resource_scoping[action] = _apply_customer_context(
                        action, resource_scoping[action], aws_config,
                        s3_config, ec2_config, rds_config, iam_config
                    )

        grouped = _group_by_service(all_permissions)

        return {
            "selected_features": selected,
            "all_permissions": sorted(all_permissions),
            "permissions_by_service": grouped,
            "resource_scoping": resource_scoping,
            "total_count": len(all_permissions),
        }

    def list_features(self) -> list[dict[str, str]]:
        """Return all available features with display names and risk levels."""
        result = []
        for key in self._mapper.feature_keys:
            result.append({
                "key": key,
                "display_name": FEATURE_DISPLAY_NAMES.get(key, key),
                "risk_level": self._mapper.get_risk_level(key),
                "description": self._mapper.get_feature(key).get("description", ""),
            })
        return result


def _group_by_service(permissions: list[str]) -> dict[str, list[str]]:
    """Group IAM action strings by their service prefix (e.g. 'ec2', 'rds')."""
    groups: dict[str, list[str]] = {}
    for perm in sorted(permissions):
        parts = perm.split(":", 1)
        service = parts[0].lower() if len(parts) == 2 else "other"
        groups.setdefault(service, []).append(perm)
    return dict(sorted(groups.items()))


def _apply_customer_context(
    action: str,
    rule: dict[str, Any],
    aws_config: dict,
    s3_config: dict,
    ec2_config: dict,
    rds_config: dict,
    iam_config: dict,
) -> dict[str, Any]:
    """Substitute customer-specific values into resource scoping rules."""
    account = aws_config.get("account_id", "{account}")
    regions = aws_config.get("regions", ["{region}"])
    region = regions[0] if regions else "{region}"
    tag_key = aws_config.get("tag_key", "CohesityManaged")
    tag_value = aws_config.get("tag_value", "true")

    bucket_pattern = s3_config.get("bucket_pattern", "cohesity-*")
    existing_buckets = s3_config.get("existing_buckets", [])
    if existing_buckets:
        bucket_resources = [f"arn:aws:s3:::{b}" for b in existing_buckets]
        bucket_object_resources = [f"arn:aws:s3:::{b}/*" for b in existing_buckets]
    else:
        bucket_resources = [f"arn:aws:s3:::{bucket_pattern}"]
        bucket_object_resources = [f"arn:aws:s3:::{bucket_pattern}/*"]

    vpc_ids = ec2_config.get("vpc_ids", [])
    subnet_ids = ec2_config.get("subnet_ids", [])
    use_tagging = ec2_config.get("use_tagging_conditions", True)

    rds_prefix = rds_config.get("snapshot_prefix", "cohesity-")
    role_prefix = iam_config.get("role_name_prefix", "Cohesity")
    boundary_arn = iam_config.get("permissions_boundary_arn", "")

    # Get KMS key ARN from s3 config
    kms_key_arn = s3_config.get("kms_key_arn", "*")
    if not kms_key_arn:
        kms_key_arn = "*"

    def _fill(resource_val: Any) -> Any:
        """Replace template placeholders with actual customer values."""
        if isinstance(resource_val, str):
            result = (
                resource_val
                .replace("{region}", region)
                .replace("{account}", account)
                .replace("{bucket_pattern}", bucket_pattern)
                .replace("{subnet_ids}", "*" if not subnet_ids else
                         "/".join(subnet_ids))
                .replace("{role_prefix}", role_prefix)
                .replace("{snapshot_prefix}", rds_prefix)
                .replace("{tag_key}", tag_key)
                .replace("{kms_key_arn}", kms_key_arn)
            )
            return result
        if isinstance(resource_val, list):
            return [_fill(r) for r in resource_val]
        return resource_val

    new_rule = dict(rule)
    new_rule["resource"] = _fill(rule.get("resource", "*"))

    service_prefix = action.split(":")[0].lower() if ":" in action else ""

    if service_prefix == "s3":
        if action in ("s3:PutObject", "s3:GetObject", "s3:DeleteObject",
                      "s3:GetObjectVersion", "s3:DeleteObjectVersion",
                      "s3:AbortMultipartUpload", "s3:PutObjectTagging",
                      "s3:PutObjectAcl", "s3:GetObjectTagging", "s3:GetObjectAcl"):
            new_rule["resource"] = bucket_object_resources
        elif action in ("s3:ListBucket", "s3:GetBucketVersioning",
                        "s3:GetBucketPolicy", "s3:GetBucketAcl",
                        "s3:GetLifecycleConfiguration", "s3:GetEncryptionConfiguration",
                        "s3:ListBucketMultipartUploads", "s3:ListBucketVersions",
                        "s3:GetBucketObjectLockConfiguration",
                        "s3:CreateBucket", "s3:PutLifecycleConfiguration",
                        "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration"):
            new_rule["resource"] = bucket_resources

    if service_prefix == "ec2" and use_tagging:
        condition_keys = new_rule.get("condition_keys", [])
        tag_conditions: dict[str, Any] = {}
        if "aws:RequestTag/CohesityManaged" in condition_keys:
            tag_conditions["StringEquals"] = {
                f"aws:RequestTag/{tag_key}": tag_value
            }
        elif "ec2:ResourceTag/CohesityManaged" in condition_keys:
            tag_conditions["StringEquals"] = {
                f"ec2:ResourceTag/{tag_key}": tag_value
            }
        if tag_conditions:
            new_rule["conditions"] = tag_conditions

    if service_prefix == "iam" and role_prefix:
        resource = new_rule.get("resource", [])
        if isinstance(resource, list):
            new_rule["resource"] = [
                r.replace("Cohesity", role_prefix) for r in resource
            ]
        elif isinstance(resource, str):
            new_rule["resource"] = resource.replace("Cohesity", role_prefix)

        if action == "iam:CreateRole" and boundary_arn:
            new_rule["conditions"] = {
                "StringEquals": {
                    "iam:PermissionsBoundary": boundary_arn
                }
            }

    return new_rule
