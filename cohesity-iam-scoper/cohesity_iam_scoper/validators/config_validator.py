"""Config validator - validates cohesity-config.json before generation."""

import re
from typing import Any

_ACCOUNT_ID_RE = re.compile(r'^\d{12}$')
_ROLE_PREFIX_RE = re.compile(r'^[A-Za-z][A-Za-z0-9]*$')
_BOUNDARY_ARN_RE = re.compile(r'^arn:aws:iam::\d{12}:policy/.+$')

# Fields that are collected in config but not yet wired into policy generation.
_UNIMPLEMENTED_FIELDS: list[tuple[str, str, str]] = [
    ("ec2.instance_types", "ec2", "instance_types"),
    ("rds.allowed_engines", "rds", "allowed_engines"),
    ("redshift.db_users", "redshift", "db_users"),
]


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

    # --- selected_features: warn on unknown keys ---
    from cohesity_iam_scoper.mappers.permission_map import PermissionMapper
    valid_keys = set(PermissionMapper().feature_keys)
    selected = config.get("selected_features", [])
    unknown = [f for f in selected if f not in valid_keys]
    if unknown:
        warnings.append(
            f"Unknown feature key(s) in selected_features (will be skipped): "
            f"{', '.join(unknown)}"
        )

    # --- Warn on config fields collected but not yet applied ---
    for field_name, section_key, field_key in _UNIMPLEMENTED_FIELDS:
        section = config.get(section_key, {})
        value = section.get(field_key)
        if value:
            warnings.append(
                f"{field_name} is set but not yet applied to generated policies."
            )

    return errors, warnings
