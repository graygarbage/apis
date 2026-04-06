"""CloudFormation template generator.

Produces a full CFT with scoped IAM roles matching the structure of the
existing Cohesity cft.json but with minimal, least-privilege permissions.
"""

from typing import Any


_ROLE_DESCRIPTIONS = {
    "CohesitySourceRegistrationRole": (
        "Cohesity source registration and discovery role - "
        "read-only AWS resource discovery"
    ),
    "CohesityArchiveRole": (
        "Cohesity archive role - scoped S3/Glacier write access"
    ),
    "CohesityBackupRole": (
        "Cohesity backup role - EC2/RDS snapshot operations"
    ),
    "CohesityRestoreRole": (
        "Cohesity restore role - EC2/RDS instance recovery"
    ),
    "CohesityInstanceRole": (
        "Cohesity instance role - attached to Cohesity EC2 instances"
    ),
    "CohesityBackupS3StagingRole": (
        "Cohesity RDS S3 staging role - temporary S3 staging for RDS restores"
    ),
}

FEATURE_TO_ROLE = {
    "source_registration_aws": "CohesitySourceRegistrationRole",
    "ec2_vm_backup": "CohesityBackupRole",
    "rds_backup": "CohesityBackupRole",
    "dynamodb_backup": "CohesityBackupRole",
    "ec2_vm_restore": "CohesityRestoreRole",
    "rds_restore": "CohesityRestoreRole",
    "s3_archive": "CohesityArchiveRole",
    "glacier_archive": "CohesityArchiveRole",
    "rds_staging_s3": "CohesityBackupS3StagingRole",
    "iam_role_management": "CohesitySourceRegistrationRole",
    "ssm_operations": "CohesityBackupRole",
    "cloudformation_management": "CohesitySourceRegistrationRole",
    "kms_encryption": "CohesityArchiveRole",
}


class CFTGenerator:
    """Generates CloudFormation templates with scoped IAM roles."""

    def generate(
        self, permissions: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a CloudFormation template.

        Args:
            permissions: Output from FeatureDetector.resolve_permissions().
            config: Customer configuration dict.

        Returns:
            CloudFormation template dict ready to serialise as JSON.
        """
        selected_features = permissions.get("selected_features", [])
        resource_scoping = permissions.get("resource_scoping", {})
        by_service = permissions.get("permissions_by_service", {})

        aws_config = config.get("aws", {})
        account_id = aws_config.get("account_id", "")
        tag_key = aws_config.get("tag_key", "CohesityManaged")
        tag_value = aws_config.get("tag_value", "true")

        role_to_perms: dict[str, dict[str, list[str]]] = {}
        for feature_key in selected_features:
            role_name = FEATURE_TO_ROLE.get(feature_key, "CohesitySourceRegistrationRole")
            role_to_perms.setdefault(role_name, {})

        all_perms = permissions.get("all_permissions", [])
        default_role = "CohesitySourceRegistrationRole"
        for perm in all_perms:
            service = perm.split(":")[0].lower() if ":" in perm else "other"
            assigned = False
            for feature_key in selected_features:
                role_name = FEATURE_TO_ROLE.get(feature_key)
                if not role_name:
                    continue
                from cohesity_iam_scoper.mappers.permission_map import PermissionMapper
                mapper = PermissionMapper()
                if perm in mapper.get_required_permissions(feature_key):
                    role_to_perms.setdefault(role_name, {}).setdefault(
                        service, []
                    )
                    if perm not in role_to_perms[role_name][service]:
                        role_to_perms[role_name][service].append(perm)
                    assigned = True
                    break
            if not assigned:
                role_to_perms.setdefault(default_role, {}).setdefault(
                    service, []
                )
                if perm not in role_to_perms[default_role][service]:
                    role_to_perms[default_role][service].append(perm)

        cft_resources: dict[str, Any] = {}
        outputs: dict[str, Any] = {}

        for role_name, perms_by_service in role_to_perms.items():
            if not perms_by_service:
                continue

            statements = _build_statements(perms_by_service, resource_scoping)
            if not statements:
                continue

            trust_policy = _build_trust_policy(role_name, account_id)

            cft_resources[role_name] = {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "Description": _ROLE_DESCRIPTIONS.get(role_name, role_name),
                    "AssumeRolePolicyDocument": trust_policy,
                    "Tags": [
                        {"Key": tag_key, "Value": tag_value},
                        {"Key": "GeneratedBy", "Value": "cohesity-iam-scoper"},
                    ],
                    "Policies": [
                        {
                            "PolicyName": f"{role_name}Policy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": statements,
                            },
                        }
                    ],
                },
            }

            logical_output = f"{role_name}Arn"
            outputs[logical_output] = {
                "Value": {"Fn::GetAtt": [role_name, "Arn"]},
                "Description": f"ARN of {role_name}",
                "Export": {"Name": {"Fn::Sub": f"${{AWS::StackName}}-{logical_output}"}},
            }

        iam_config = config.get("iam", {})
        boundary_arn = iam_config.get("permissions_boundary_arn", "")

        parameters: dict[str, Any] = {
            "CohesityTagKey": {
                "Type": "String",
                "Default": tag_key,
                "Description": "Tag key applied to all Cohesity-managed resources",
            },
            "CohesityTagValue": {
                "Type": "String",
                "Default": tag_value,
                "Description": "Tag value applied to all Cohesity-managed resources",
            },
        }

        s3_config = config.get("s3", {})
        bucket_pattern = s3_config.get("bucket_pattern", "cohesity-*")
        if bucket_pattern:
            parameters["ArchiveBucketPattern"] = {
                "Type": "String",
                "Default": bucket_pattern,
                "Description": "S3 bucket name pattern for Cohesity archive buckets",
            }

        if boundary_arn:
            parameters["PermissionsBoundaryArn"] = {
                "Type": "String",
                "Default": boundary_arn,
                "Description": "Permissions boundary ARN to attach to Cohesity IAM roles",
            }

        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": (
                "Cohesity Cloud Edition - Scoped IAM Roles "
                "(generated by cohesity-iam-scoper v1.0.0)"
            ),
            "Parameters": parameters,
            "Resources": cft_resources,
            "Outputs": outputs,
        }


def _build_trust_policy(role_name: str, account_id: str) -> dict[str, Any]:
    """Build a role trust policy."""
    principal: Any
    if account_id:
        principal = {"AWS": f"arn:aws:iam::{account_id}:root"}
    else:
        principal = {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}}

    if role_name == "CohesityInstanceRole":
        principal = {"Service": "ec2.amazonaws.com"}
    elif "Archive" in role_name or "Staging" in role_name:
        principal = {
            "AWS": account_id or {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}
        }

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": principal,
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _build_statements(
    perms_by_service: dict[str, list[str]],
    resource_scoping: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build CFT IAM statements from permissions grouped by service."""
    statements: list[dict[str, Any]] = []

    for service, actions in perms_by_service.items():
        scoped: dict[str, list[str]] = {}
        unscoped: list[str] = []

        for action in sorted(actions):
            rule = resource_scoping.get(action)
            if rule:
                resource = rule.get("resource", "*")
                key = _resource_key(resource)
                scoped.setdefault(key, []).append(action)
            else:
                unscoped.append(action)

        for resource_key, acts in scoped.items():
            resource = _parse_resource_key(resource_key)
            rule = resource_scoping.get(acts[0], {})
            conditions = rule.get("conditions")
            stmt: dict[str, Any] = {
                "Sid": f"{service.upper()}Scoped{len(statements)}",
                "Effect": "Allow",
                "Action": sorted(acts),
                "Resource": resource,
            }
            if conditions:
                stmt["Condition"] = conditions
            statements.append(stmt)

        if unscoped:
            statements.append({
                "Sid": f"{service.upper()}ReadOnly{len(statements)}",
                "Effect": "Allow",
                "Action": sorted(unscoped),
                "Resource": "*",
            })

    return statements


def _resource_key(resource: Any) -> str:
    if isinstance(resource, list):
        return "||".join(sorted(resource))
    return str(resource)


def _parse_resource_key(key: str) -> Any:
    if "||" in key:
        return key.split("||")
    return key
