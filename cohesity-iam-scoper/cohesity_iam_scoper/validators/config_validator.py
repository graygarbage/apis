"""Config validator - validates cohesity-config.json before generation."""

import re
from typing import Any

_ACCOUNT_ID_RE = re.compile(r'^\d{12}$')
_ROLE_PREFIX_RE = re.compile(r'^[A-Za-z][A-Za-z0-9]*$')
_BOUNDARY_ARN_RE = re.compile(r'^arn:aws:iam::\d{12}:policy/.+$')

# Fields that are collected in config but not yet wired into policy generation.
_UNIMPLEMENTED_FIELDS: list[tuple[str, str, str]] = [
    ("redshift.db_users", "redshift", "db_users"),
]

# Feature groups used for feature-conditional scoping checks.
_EC2_FEATURES = frozenset({"ec2_vm_backup", "ec2_vm_restore", "ssm_operations"})
_RDS_FEATURES = frozenset({"rds_backup", "rds_restore", "rds_db_connect", "rds_staging_s3"})
_REDSHIFT_FEATURES = frozenset({"redshift_backup"})
_DYNAMODB_FEATURES = frozenset({"dynamodb_backup"})
_KMS_FEATURES = frozenset({"kms_encryption"})


def validate_config(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Validate a cohesity-config.json dict before policy generation.

    Args:
        config: Configuration dict loaded from the config file.

    Returns:
        (errors, warnings): errors are fatal and block generation;
        warnings are advisory and printed but do not stop generation.
    """
    errors: list[str] = []
    warnings: list[str] = []

    aws = config.get("aws", {})
    iam = config.get("iam", {})

    # --- aws.account_id: must be exactly 12 digits when provided ---
    account_id = str(aws.get("account_id", "") or "")
    if account_id and not _ACCOUNT_ID_RE.match(account_id):
        errors.append(
            f"aws.account_id '{account_id}' is invalid: must be exactly 12 digits."
        )

    # --- aws.cohesity_account_id: same format ---
    cohesity_account_id = str(aws.get("cohesity_account_id", "") or "")
    if cohesity_account_id and not _ACCOUNT_ID_RE.match(cohesity_account_id):
        errors.append(
            f"aws.cohesity_account_id '{cohesity_account_id}' is invalid: must be exactly 12 digits."
        )

    # --- iam.role_name_prefix: letter then alphanumeric ---
    role_prefix = str(iam.get("role_name_prefix", "") or "")
    if role_prefix and not _ROLE_PREFIX_RE.match(role_prefix):
        errors.append(
            f"iam.role_name_prefix '{role_prefix}' is invalid: "
            "must start with a letter and contain only alphanumeric characters."
        )

    # --- iam.permissions_boundary_arn: valid ARN format when provided ---
    use_pb = bool(iam.get("use_permissions_boundary", False))
    pb_arn = str(iam.get("permissions_boundary_arn", "") or "")
    if pb_arn and not _BOUNDARY_ARN_RE.match(pb_arn):
        errors.append(
            f"iam.permissions_boundary_arn '{pb_arn}' is not a valid IAM policy ARN. "
            "Expected format: arn:aws:iam::<12-digit-account>:policy/<name>"
        )

    # When boundary is enabled with no explicit ARN, auto-generation requires account_id.
    if use_pb and not pb_arn and not account_id:
        errors.append(
            "iam.use_permissions_boundary is true but neither iam.permissions_boundary_arn "
            "nor aws.account_id is set. Cannot generate a valid boundary ARN."
        )

    # --- selected_features: required key ---
    if "selected_features" not in config:
        errors.append(
            "selected_features is required but missing from config. "
            "Run 'cohesity-iam-scoper configure' to generate a valid config."
        )

    from cohesity_iam_scoper.mappers.permission_map import PermissionMapper
    valid_keys = set(PermissionMapper().feature_keys)
    selected = config.get("selected_features", [])

    if "selected_features" in config and not selected:
        warnings.append(
            "selected_features is empty — all features will be included, "
            "significantly broadening the generated permissions."
        )

    # --- selected_features: warn on unknown keys ---
    unknown = [f for f in selected if f not in valid_keys]
    if unknown:
        warnings.append(
            f"Unknown feature key(s) in selected_features (will be skipped): "
            f"{', '.join(unknown)}"
        )

    # --- aws.tag_value: warn on wildcard characters ---
    tag_value = str(aws.get("tag_value", "") or "")
    if "*" in tag_value or "?" in tag_value:
        warnings.append(
            f"aws.tag_value '{tag_value}' contains a wildcard character. "
            "Tag values are embedded in StringLike conditions and wildcards broaden "
            "the match beyond the intended resource set. Use a literal value."
        )

    # --- Warn on config fields collected but not yet applied ---
    for field_name, section_key, field_key in _UNIMPLEMENTED_FIELDS:
        section = config.get(section_key, {})
        value = section.get(field_key)
        if value:
            warnings.append(
                f"{field_name} is set but not yet applied to generated policies."
            )

    # --- Feature-conditional scoping checks ---
    # These are advisory: missing inputs degrade scoping quality but do not block generation.
    selected_set = set(selected)

    if _EC2_FEATURES & selected_set:
        ec2 = config.get("ec2", {})
        if not ec2.get("vpc_ids"):
            warnings.append(
                "EC2 features selected but ec2.vpc_ids is empty — "
                "RunInstances and network operations will be unscoped to a specific VPC."
            )
        if not ec2.get("subnet_ids"):
            warnings.append(
                "EC2 features selected but ec2.subnet_ids is empty — "
                "RunInstances will be unscoped to specific subnets."
            )

    if _RDS_FEATURES & selected_set:
        rds = config.get("rds", {})
        if not rds.get("snapshot_prefix"):
            warnings.append(
                "rds.snapshot_prefix is empty — RDS snapshot ARNs will use a wildcard prefix, "
                "granting snapshot access across all DB snapshots in the account."
            )

    if _REDSHIFT_FEATURES & selected_set:
        redshift = config.get("redshift", {})
        if not redshift.get("cluster_identifiers"):
            warnings.append(
                "redshift_backup selected but redshift.cluster_identifiers is empty — "
                "Redshift permissions will apply to all clusters in the account."
            )

    if _DYNAMODB_FEATURES & selected_set:
        dynamodb = config.get("dynamodb", {})
        if not dynamodb.get("table_name_pattern") and not dynamodb.get("table_name_patterns"):
            warnings.append(
                "dynamodb_backup selected but dynamodb.table_name_pattern is empty — "
                "DynamoDB data-plane permissions will apply to all tables (Resource: table/*)."
            )
        if not dynamodb.get("staging_bucket_pattern"):
            warnings.append(
                "dynamodb_backup selected but dynamodb.staging_bucket_pattern is empty — "
                "DynamoDB export S3 staging will fall back to the general s3.bucket_pattern."
            )

    if _KMS_FEATURES & selected_set:
        kms = config.get("kms", {})
        if not kms.get("key_arns"):
            warnings.append(
                "kms_encryption selected but kms.key_arns is empty — "
                "KMS permissions will apply to all keys (Resource: \"*\")."
            )

    # --- Informational: scoping fallbacks in effect ---
    s3 = config.get("s3", {})
    bucket_pattern = s3.get("bucket_pattern", "cohesity-*")
    if bucket_pattern in ("cohesity-*", "") and not s3.get("existing_buckets"):
        warnings.append(
            "s3.bucket_pattern is using the default 'cohesity-*' — "
            "consider tightening to a company-specific prefix (e.g. acme-cohesity-*)."
        )

    ec2_cfg = config.get("ec2", {})
    if not ec2_cfg.get("use_tagging_conditions") and _EC2_FEATURES & selected_set:
        warnings.append(
            "ec2.use_tagging_conditions is disabled — EC2 resource-level conditions will not "
            "be applied. Enable to restrict EC2 manage/delete actions to Cohesity-tagged resources."
        )

    return errors, warnings
