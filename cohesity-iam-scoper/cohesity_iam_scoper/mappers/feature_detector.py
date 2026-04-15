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
            import warnings
            warnings.warn(
                "selected_features is empty — including ALL features. "
                "Run 'cohesity-iam-scoper configure' to select only the features you need "
                "and reduce permissions by up to 45%.",
                UserWarning,
                stacklevel=2,
            )
            selected = self._mapper.feature_keys

        s3_config = config.get("s3", {})
        ec2_config = config.get("ec2", {})
        rds_config = config.get("rds", {})
        iam_config = config.get("iam", {})
        aws_config = config.get("aws", {})
        kms_config = config.get("kms", {})
        dynamodb_config = config.get("dynamodb", {})
        redshift_config = config.get("redshift", {})
        glue_config = config.get("glue", {})

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
                        s3_config, ec2_config, rds_config, iam_config,
                        kms_config=kms_config,
                        dynamodb_config=dynamodb_config,
                        redshift_config=redshift_config,
                        glue_config=glue_config,
                        feature_key=feature_key,
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


# EC2 actions that operate on pre-existing CUSTOMER-OWNED resources.
# Tag conditions must not be applied here — the customer's resources won't
# have Cohesity tags pre-applied before the first backup runs.
# Contrast with ec2:TerminateInstances / ec2:DeleteVolume / ec2:DeleteSnapshot
# which only ever touch resources Cohesity itself created (and tagged).
_EC2_CUSTOMER_RESOURCE_ACTIONS = {
    "ec2:CreateSnapshot",        # source is the customer's EBS volume
    "ec2:AttachVolume",          # may touch customer volumes
    "ec2:DetachVolume",
    "ec2:ModifyInstanceAttribute",
    "ec2:ModifySnapshotAttribute",
    "ec2:CopySnapshot",          # source snapshot may predate Cohesity
    "ec2:RunInstances",          # Cohesity Fleet instances use UniqueTag, not CohesityManaged
    "ec2:CreateTags",            # Tags Fleet instance immediately after RunInstances (before tag exists)
    "ec2:CreateVolume",          # Fleet creates volumes from snapshot before tagging
    "ec2:StartInstances",        # Called after RunInstances but before CohesityManaged tag is applied
    "ec2:TerminateInstances",    # TEMP: fleet instances may not be tagged if Cohesity UI bug persists
    "ec2:DeleteVolume",          # TEMP: fleet volume cleanup
    # SG/NI/image actions operate on resources that may predate or be unrelated to Cohesity
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:CreateSecurityGroup",
    "ec2:CreateImage",
    "ec2:CreateInstanceExportTask",
    "ec2:AttachNetworkInterface",
    "ec2:DetachNetworkInterface",
    "ec2:DeleteNetworkInterface",
    "ec2:CreateNetworkInterface",
    "ec2:ModifyNetworkInterfaceAttribute",
}


def _group_by_service(permissions: list[str]) -> dict[str, list[str]]:
    """Group IAM action strings by their service prefix (e.g. 'ec2', 'rds')."""
    groups: dict[str, list[str]] = {}
    for perm in sorted(permissions):
        parts = perm.split(":", 1)
        service = parts[0].lower() if len(parts) == 2 else "other"
        groups.setdefault(service, []).append(perm)
    return dict(sorted(groups.items()))


_GLUE_JOB_ACTIONS = {
    "glue:CreateJob",
    "glue:DeleteJob",
    "glue:GetJobRun",
    "glue:StartJobRun",
    "glue:UpdateJob",
}


def _apply_customer_context(
    action: str,
    rule: dict[str, Any],
    aws_config: dict,
    s3_config: dict,
    ec2_config: dict,
    rds_config: dict,
    iam_config: dict,
    *,
    kms_config: Optional[dict] = None,
    dynamodb_config: Optional[dict] = None,
    redshift_config: Optional[dict] = None,
    glue_config: Optional[dict] = None,
    feature_key: str = "",
) -> dict[str, Any]:
    """Substitute customer-specific values into resource scoping rules."""
    kms_config = kms_config or {}
    dynamodb_config = dynamodb_config or {}
    redshift_config = redshift_config or {}
    glue_config = glue_config or {}
    account = aws_config.get("account_id", "") or "${AWS::AccountId}"
    region = "*"  # IAM resource ARNs use wildcard region (matches Cohesity's own template)
    # Cohesity's production tag key is "UniqueTag" with value pattern "cohesity_*".
    # The original cft.json uses StringLike + cohesity_* on manage/delete actions for
    # Glue, SQS, and EventBridge. Use these as safe defaults.
    tag_key = aws_config.get("tag_key", "UniqueTag")
    tag_value = aws_config.get("tag_value", "cohesity")

    _bucket_pattern_raw = s3_config.get("bucket_pattern", "cohesity-*")
    # Accept either a single string or a list of patterns.
    if isinstance(_bucket_pattern_raw, list):
        bucket_patterns = [p.strip() for p in _bucket_pattern_raw if p.strip()]
    else:
        bucket_patterns = [p.strip() for p in _bucket_pattern_raw.split(",") if p.strip()]
    if not bucket_patterns:
        bucket_patterns = ["cohesity-*"]
    # Keep the first pattern for single-value template placeholders ({bucket_pattern}).
    bucket_pattern = bucket_patterns[0]

    existing_buckets = s3_config.get("existing_buckets", [])
    if existing_buckets:
        bucket_resources = [f"arn:aws:s3:::{b}" for b in existing_buckets]
        bucket_object_resources = [f"arn:aws:s3:::{b}/*" for b in existing_buckets]
    else:
        # Include all user-supplied patterns plus chsty-* (restore staging).
        bucket_resources = [f"arn:aws:s3:::{p}" for p in bucket_patterns] + ["arn:aws:s3:::chsty-*"]
        bucket_object_resources = [f"arn:aws:s3:::{p}/*" for p in bucket_patterns] + ["arn:aws:s3:::chsty-*/*"]

    vpc_ids = ec2_config.get("vpc_ids", [])
    subnet_ids = ec2_config.get("subnet_ids", [])
    # EC2 tagging is opt-in: the original template never conditioned EC2 actions,
    # so enabling it by default is speculative and may break deployments.
    use_tagging = ec2_config.get("use_tagging_conditions", False)

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
                      "s3:PutObjectAcl", "s3:GetObjectTagging", "s3:GetObjectAcl",
                      "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging",
                      "s3:GetObjectAttributes", "s3:GetObjectTorrent",
                      "s3:GetObjectVersionAcl", "s3:GetObjectVersionAttributes",
                      "s3:GetObjectVersionTagging", "s3:GetObjectVersionTorrent",
                      "s3:HeadObject", "s3:ListMultipartUploadParts",
                      "s3:PutObjectRetention", "s3:PutObjectVersionAcl",
                      "s3:PutObjectVersionTagging", "s3:RestoreObject"):
            new_rule["resource"] = bucket_object_resources
        elif action in ("s3:ListBucket", "s3:GetBucketVersioning",
                        "s3:GetBucketPolicy", "s3:GetBucketAcl",
                        "s3:GetLifecycleConfiguration", "s3:GetEncryptionConfiguration",
                        "s3:ListBucketMultipartUploads", "s3:ListBucketVersions",
                        "s3:GetBucketObjectLockConfiguration",
                        "s3:GetIntelligentTieringConfiguration",
                        "s3:CreateBucket", "s3:PutLifecycleConfiguration",
                        "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
                        "s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock",
                        "s3:PutBucketAcl", "s3:PutBucketTagging",
                        "s3:DeleteBucket", "s3:GetBucketLocation",
                        "s3:PutBucketPolicy", "s3:PutBucketNotification",
                        "s3:PutInventoryConfiguration", "s3:GetBucketNotification",
                        "s3:GetInventoryConfiguration", "s3:GetBucketOwnershipControls"):
            new_rule["resource"] = bucket_resources

    # --- EC2 VPC/subnet scoping: narrow wildcard ARNs to specific IDs when provided ---
    if service_prefix == "ec2" and (vpc_ids or subnet_ids):
        resource = new_rule.get("resource", "*")
        if isinstance(resource, list):
            expanded: list[Any] = []
            for r in resource:
                if vpc_ids and isinstance(r, str) and r.endswith(":vpc/*"):
                    expanded.extend(
                        r[: r.rfind("/")] + f"/{vid}" for vid in vpc_ids
                    )
                elif subnet_ids and isinstance(r, str) and r.endswith(":subnet/*"):
                    expanded.extend(
                        r[: r.rfind("/")] + f"/{sid}" for sid in subnet_ids
                    )
                else:
                    expanded.append(r)
            new_rule["resource"] = expanded

    if service_prefix == "ec2" and use_tagging and action not in _EC2_CUSTOMER_RESOURCE_ACTIONS:
        condition_keys = new_rule.get("condition_keys", [])
        tag_conditions: dict[str, Any] = {}
        if any(k.startswith("aws:RequestTag/") for k in condition_keys):
            # aws:RequestTag — Cohesity must supply the tag at creation time.
            # Applied to actions that CREATE new resources (RunInstances, CreateVolume, etc.)
            tag_conditions["StringLike"] = {
                f"aws:RequestTag/{tag_key}": tag_value
            }
        elif any(k.startswith("ec2:ResourceTag/") for k in condition_keys):
            # ec2:ResourceTag — resource must already carry the Cohesity tag.
            # Only safe for resources Cohesity itself created and tagged.
            tag_conditions["StringLike"] = {
                f"ec2:ResourceTag/{tag_key}": tag_value
            }
        if tag_conditions:
            new_rule["conditions"] = tag_conditions

    if service_prefix == "kms":
        condition_keys = new_rule.get("condition_keys", [])
        if "kms:ViaService" in condition_keys:
            # kms:ViaService restricts KMS usage to specific AWS service integrations,
            # preventing direct CLI/SDK calls to Cohesity-managed keys.
            # NOTE: validate service list against deployed Cohesity features before shipping.
            new_rule["conditions"] = {
                "StringLike": {
                    "kms:ViaService": [
                        "ec2.*.amazonaws.com",
                        "rds.*.amazonaws.com",
                        "s3.*.amazonaws.com",
                        "dynamodb.*.amazonaws.com",
                        "redshift.*.amazonaws.com",
                    ]
                }
            }
        elif "kms:GrantIsForAWSResource" in condition_keys:
            # kms:GrantIsForAWSResource restricts CreateGrant to calls made by AWS
            # services on behalf of the caller, blocking direct attacker grant creation.
            new_rule["conditions"] = {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }

    if service_prefix == "iam":
        condition_keys = new_rule.get("condition_keys", [])
        if "iam:PermissionsBoundary" in condition_keys:
            use_pb = iam_config.get("use_permissions_boundary", False)
            pb_arn = iam_config.get("permissions_boundary_arn", "")
            if use_pb:
                if not pb_arn:
                    role_prefix_val = iam_config.get("role_name_prefix", "Cohesity")
                    if account.startswith("${"):
                        # account_id not supplied; use CFT Fn::Sub so the ARN resolves
                        # at deploy time rather than embedding a broken literal placeholder.
                        pb_arn_condition_value: Any = {
                            "Fn::Sub": (
                                "arn:aws:iam::${AWS::AccountId}:policy/"
                                "${RoleNamePrefix}PermissionsBoundary"
                            )
                        }
                    else:
                        pb_arn_condition_value = (
                            f"arn:aws:iam::{account}:policy/{role_prefix_val}PermissionsBoundary"
                        )
                else:
                    pb_arn_condition_value = pb_arn
                new_rule["conditions"] = {
                    "StringEquals": {"iam:PermissionsBoundary": pb_arn_condition_value}
                }

    if service_prefix not in ("ec2", "s3", "iam", "kms"):
        # Generic handler for services that use aws:ResourceTag (Glue, SQS, EventBridge).
        # These conditions are always applied — the original cft.json proves Cohesity tags
        # these resources in production (UniqueTag: cohesity_*). Not gated by use_tagging_conditions
        # because that flag is for speculative EC2 scoping only.
        # Only applied to manage/delete actions — create actions intentionally have no
        # condition_keys, matching the original cft.json pattern where Cohesity creates
        # freely but can only manage resources it tagged with UniqueTag: cohesity_*.
        condition_keys = new_rule.get("condition_keys", [])
        if any(k.startswith("aws:ResourceTag/") for k in condition_keys):
            new_rule["conditions"] = {
                "StringLike": {
                    f"aws:ResourceTag/{tag_key}": tag_value
                }
            }

    # --- DynamoDB staging bucket override (Flag 5 fix) ---
    # When processing s3 actions on behalf of the dynamodb_backup feature,
    # use the dynamodb-specific staging bucket pattern instead of the general pattern.
    if service_prefix == "s3" and feature_key == "dynamodb_backup":
        staging_pat = dynamodb_config.get("staging_bucket_pattern", "")
        if staging_pat:
            new_rule["resource"] = [
                f"arn:aws:s3:::{staging_pat}",
                f"arn:aws:s3:::{staging_pat}/*",
            ]

    # --- DynamoDB table name pattern ---
    if service_prefix == "dynamodb":
        table_pat = dynamodb_config.get("table_name_pattern", "")
        if table_pat:
            def _sub_table(r: Any) -> Any:
                if isinstance(r, str):
                    return r.replace("table/*", f"table/{table_pat}")
                if isinstance(r, list):
                    return [_sub_table(i) for i in r]
                return r
            new_rule["resource"] = _sub_table(new_rule.get("resource", "*"))

    # --- KMS key ARN scoping ---
    if service_prefix == "kms":
        key_arns = kms_config.get("key_arns", [])
        if key_arns:
            new_rule["resource"] = key_arns if len(key_arns) > 1 else key_arns[0]

    # --- Redshift cluster scoping ---
    if service_prefix in ("redshift", "redshift-data"):
        cluster_ids = redshift_config.get("cluster_identifiers", [])
        db_users_list = redshift_config.get("db_users", [])
        if cluster_ids:
            resource = new_rule.get("resource", "*")
            if isinstance(resource, str):
                if "cluster:*" in resource:
                    new_rule["resource"] = [
                        resource.replace("cluster:*", f"cluster:{cid}")
                        for cid in cluster_ids
                    ]
                elif "dbuser:*/*" in resource:
                    if db_users_list:
                        new_rule["resource"] = [
                            resource.replace("dbuser:*/*", f"dbuser:{cid}/{u}")
                            for cid in cluster_ids
                            for u in db_users_list
                        ]
                    else:
                        new_rule["resource"] = [
                            resource.replace("dbuser:*/*", f"dbuser:{cid}/*")
                            for cid in cluster_ids
                        ]
                elif "dbname:*/*" in resource:
                    new_rule["resource"] = [
                        resource.replace("dbname:*/*", f"dbname:{cid}/*")
                        for cid in cluster_ids
                    ]

    # --- Glue job prefix scoping ---
    if service_prefix == "glue" and action in _GLUE_JOB_ACTIONS:
        job_prefix = glue_config.get("job_name_prefix", "")
        if job_prefix:
            new_rule["resource"] = (
                f"arn:aws:glue:{region}:{account}:job/{job_prefix}*"
            )

    # --- EC2 security group ID scoping ---
    if service_prefix == "ec2":
        sg_ids = ec2_config.get("security_group_ids", [])
        if sg_ids and action in (
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:CreateSecurityGroup",
        ):
            new_rule["resource"] = [
                f"arn:aws:ec2:{region}:{account}:security-group/{sg_id}"
                for sg_id in sg_ids
            ]

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
