"""CloudFormation template generator.

Produces a full CFT with scoped IAM roles matching the structure of the
existing Cohesity cft.json but with minimal, least-privilege permissions.
"""

import json as _json
import os as _os
from typing import Any

# AWS hard limits (bytes)
_INLINE_POLICY_LIMIT = 9_500   # leave buffer below 10,240 combined inline limit
_ROLE_INLINE_LIMIT   = 9_500   # combined size of ALL inline policies per role (AWS max: 10,240)
_MANAGED_POLICY_LIMIT = 5_800  # leave buffer below 6,144 per managed policy

_CANONICAL_PREFIX = "Cohesity"


def _sub_name(canonical: str, suffix: str = "") -> dict:
    """Return a CFT Fn::Sub expression using the RoleNamePrefix parameter.

    e.g. _sub_name("CohesitySourceRegistrationRole")
         → {"Fn::Sub": "${RoleNamePrefix}SourceRegistrationRole"}
    """
    base = canonical[len(_CANONICAL_PREFIX):] if canonical.startswith(_CANONICAL_PREFIX) else canonical
    return {"Fn::Sub": f"${{RoleNamePrefix}}{base}{suffix}"}


_CFT_MAP_FILE = _os.path.join(
    _os.path.dirname(__file__), "..", "..", "data", "cft_policy_feature_map.json"
)


def _load_policy_groups() -> dict[str, dict[str, list[str]]]:
    """Load cft_policy_feature_map.json → {role_name: {policy_name: [feature_keys]}}."""
    with open(_os.path.realpath(_CFT_MAP_FILE)) as fh:
        raw: dict[str, list[str]] = _json.load(fh)
    result: dict[str, dict[str, list[str]]] = {}
    for key, features in raw.items():
        role_name, policy_name = key.split("/", 1)
        result.setdefault(role_name, {})[policy_name] = features
    return result


def _policy_label(policy_name: str) -> Any:
    """PolicyName for inline policies: Fn::Sub for Cohesity-prefixed, plain string otherwise."""
    if policy_name.startswith(_CANONICAL_PREFIX):
        base = policy_name[len(_CANONICAL_PREFIX):]
        return {"Fn::Sub": f"${{RoleNamePrefix}}{base}"}
    return policy_name


def _managed_policy_name(role_name: str, policy_name: str, suffix: str = "") -> Any:
    """Unique managed policy name: {RoleNamePrefix}{RoleBase}-{policy_base}{suffix}.

    e.g. (CohesitySourceRegistrationRole, source-regis-access)
         → {"Fn::Sub": "${RoleNamePrefix}SourceRegistrationRole-source-regis-access"}
    """
    role_base = (
        role_name[len(_CANONICAL_PREFIX):]
        if role_name.startswith(_CANONICAL_PREFIX)
        else role_name
    )
    policy_base = (
        policy_name[len(_CANONICAL_PREFIX):]
        if policy_name.startswith(_CANONICAL_PREFIX)
        else policy_name
    )
    return {"Fn::Sub": f"${{RoleNamePrefix}}{role_base}-{policy_base}{suffix}"}


def _policy_logical_id(role_name: str, policy_name: str) -> str:
    """Alphanumeric CloudFormation logical ID for a managed policy resource."""
    sanitized = "".join(
        ch
        for ch in policy_name.replace("-", " ").title().replace(" ", "")
        if ch.isalnum()
    )
    return f"{role_name}{sanitized}"


_ROLE_DESCRIPTIONS = {
    "CohesitySourceRegistrationRole": (
        "Cohesity primary role - source registration, backup, and restore operations"
    ),
    "CohesityArchiveRole": (
        "Cohesity archive role - scoped S3/Glacier write access"
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
    "ec2_vm_backup": "CohesitySourceRegistrationRole",
    "ebs_direct_api": "CohesitySourceRegistrationRole",
    "rds_backup": "CohesitySourceRegistrationRole",
    "rds_db_connect": "CohesitySourceRegistrationRole",
    "redshift_backup": "CohesitySourceRegistrationRole",
    "dynamodb_backup": "CohesitySourceRegistrationRole",
    "s3_protection": "CohesitySourceRegistrationRole",
    "ec2_vm_restore": "CohesitySourceRegistrationRole",
    "rds_restore": "CohesitySourceRegistrationRole",
    "s3_archive": "CohesityArchiveRole",
    "glacier_archive": "CohesityArchiveRole",
    "rds_staging_s3": "CohesityBackupS3StagingRole",
    "iam_role_management": "CohesitySourceRegistrationRole",
    "instance_role": "CohesityInstanceRole",
    "ssm_operations": "CohesitySourceRegistrationRole",
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

        aws_config = config.get("aws", {})
        account_id = aws_config.get("account_id", "")
        cohesity_account_id = aws_config.get("cohesity_account_id") or account_id
        tag_key = aws_config.get("tag_key", "CohesityManaged")
        tag_value = aws_config.get("tag_value", "true")
        role_name_prefix = config.get("iam", {}).get("role_name_prefix", "Cohesity")

        iam_config = config.get("iam", {})
        boundary_arn = iam_config.get("permissions_boundary_arn", "")
        use_permissions_boundary = iam_config.get("use_permissions_boundary", False)
        if use_permissions_boundary and not boundary_arn:
            _boundary_ref: Any = {"Ref": "CohesityPermissionsBoundary"}
        elif use_permissions_boundary:
            _boundary_ref = {"Ref": "PermissionsBoundaryArn"}
        else:
            _boundary_ref = None

        # Build feature → (role, policy_name) from the canonical CFT grouping.
        # This mirrors cft.json's named inline policies (source-regis-access,
        # CohesityS3Policy, CohesityDynamoDBPolicy, etc.) so generated output
        # uses descriptive names instead of positional suffixes (Policy1, Policy2, …).
        _policy_groups = _load_policy_groups()
        feature_to_policy: dict[str, tuple[str, str]] = {}
        for _r, _pp in _policy_groups.items():
            for _pn, _fks in _pp.items():
                for _fk in _fks:
                    feature_to_policy[_fk] = (_r, _pn)

        # role → policy_name → service → [unique actions]
        role_to_policies: dict[str, dict[str, dict[str, list[str]]]] = {}
        _seen_pp: dict[tuple[str, str], set[str]] = {}

        from cohesity_iam_scoper.mappers.permission_map import PermissionMapper
        mapper = PermissionMapper()

        for feature_key in selected_features:
            if feature_key not in mapper.feature_keys:
                continue
            _rn, _pn = feature_to_policy.get(
                feature_key,
                (FEATURE_TO_ROLE.get(feature_key, "CohesitySourceRegistrationRole"), "CohesityExtraOperations"),
            )
            role_to_policies.setdefault(_rn, {}).setdefault(_pn, {})
            _sent = (_rn, _pn)
            _seen_pp.setdefault(_sent, set())
            for perm in mapper.get_required_permissions(feature_key):
                if perm in _seen_pp[_sent]:
                    continue
                _seen_pp[_sent].add(perm)
                _svc = perm.split(":")[0].lower() if ":" in perm else "other"
                role_to_policies[_rn][_pn].setdefault(_svc, []).append(perm)

        cft_resources: dict[str, Any] = {}
        outputs: dict[str, Any] = {}

        for role_name, named_policies in role_to_policies.items():
            if not named_policies:
                continue

            trust_policy = _build_trust_policy(
                role_name, cohesity_account_id,
                external_id=iam_config.get("external_id", ""),
            )
            inline_policies: list[dict] = []
            managed_arns: list[Any] = []

            # Build all policy docs first so we can check the combined inline size.
            # AWS enforces a single 10,240 byte limit across ALL inline policies for
            # a role — each doc may be fine individually but blow up when combined.
            # Strategy: keep all docs that fit within _INLINE_POLICY_LIMIT each,
            # then if the combined total would exceed _ROLE_INLINE_LIMIT, promote
            # the largest policies to managed until the remainder fits.
            candidate_docs: list[tuple[str, dict]] = []  # (policy_name, policy_doc)
            for policy_name, perms_by_service in named_policies.items():
                stmts = _build_statements(perms_by_service, resource_scoping)
                if not stmts:
                    continue
                candidate_docs.append((policy_name, {"Version": "2012-10-17", "Statement": stmts}))

            # Inject boundary-protection Deny statements into SourceRegistrationRole.
            if (
                use_permissions_boundary
                and role_name == "CohesitySourceRegistrationRole"
                and "iam_role_management" in selected_features
            ):
                deny_stmts = _build_deny_statements()
                candidate_docs.append((
                    "CohesityBoundaryProtection",
                    {"Version": "2012-10-17", "Statement": deny_stmts},
                ))

            # Determine which candidates stay inline vs. become managed policies.
            # Sort largest-first so we promote the biggest offenders first.
            _doc_sizes = [(pn, doc, len(_json.dumps(doc).encode())) for pn, doc in candidate_docs]
            _combined = sum(sz for _, _, sz in _doc_sizes)
            _must_manage: set[str] = set()
            if _combined > _ROLE_INLINE_LIMIT:
                for pn, _, sz in sorted(_doc_sizes, key=lambda x: -x[2]):
                    _must_manage.add(pn)
                    _combined -= sz
                    if _combined <= _ROLE_INLINE_LIMIT:
                        break

            def _emit_managed(policy_name: str, stmts: list) -> None:
                chunks = _chunk_statements(stmts, _MANAGED_POLICY_LIMIT)
                for chunk_idx, chunk in enumerate(chunks, start=1):
                    part_suffix = f"-part{chunk_idx}" if len(chunks) > 1 else ""
                    logical_id = _policy_logical_id(role_name, policy_name)
                    if len(chunks) > 1:
                        logical_id += f"Part{chunk_idx}"
                    mp_resource: dict[str, Any] = {
                        "Type": "AWS::IAM::ManagedPolicy",
                        "Properties": {
                            "ManagedPolicyName": _managed_policy_name(
                                role_name, policy_name, part_suffix
                            ),
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": chunk,
                            },
                        },
                    }
                    if role_name == "CohesityInstanceRole":
                        mp_resource["Condition"] = "RunningCE"
                    cft_resources[logical_id] = mp_resource
                    managed_arns.append({"Ref": logical_id})

            for policy_name, policy_doc in candidate_docs:
                doc_bytes = len(_json.dumps(policy_doc).encode())
                if policy_name in _must_manage or doc_bytes > _INLINE_POLICY_LIMIT:
                    # Too large for inline (individually or combined) — use managed policy.
                    _emit_managed(policy_name, policy_doc["Statement"])
                else:
                    inline_policies.append({
                        "PolicyName": _policy_label(policy_name),
                        "PolicyDocument": policy_doc,
                    })

            if not inline_policies and not managed_arns:
                continue

            role_entry: dict[str, Any] = {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": _sub_name(role_name),
                    "Description": _ROLE_DESCRIPTIONS.get(role_name, role_name),
                    "AssumeRolePolicyDocument": trust_policy,
                    "Tags": [
                        {"Key": tag_key, "Value": tag_value},
                        {"Key": "GeneratedBy", "Value": "cohesity-iam-scoper"},
                    ],
                },
            }
            if inline_policies:
                role_entry["Properties"]["Policies"] = inline_policies
            if managed_arns:
                role_entry["Properties"]["ManagedPolicyArns"] = managed_arns
            if role_name == "CohesityInstanceRole":
                role_entry["Condition"] = "RunningCE"
            if _boundary_ref is not None:
                role_entry["Properties"]["PermissionsBoundary"] = _boundary_ref
            cft_resources[role_name] = role_entry

            # CohesityInstanceProfile is required by EC2 to attach CohesityInstanceRole
            # to Cohesity CE instances.  Only created in the CE account.
            if role_name == "CohesityInstanceRole":
                cft_resources["CohesityInstanceProfile"] = {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Condition": "RunningCE",
                    "Properties": {
                        "InstanceProfileName": _sub_name("CohesityInstanceProfile"),
                        "Roles": [{"Ref": "CohesityInstanceRole"}],
                    },
                }

            logical_output = f"{role_name}Arn"
            output_entry: dict[str, Any] = {
                "Value": {"Fn::GetAtt": [role_name, "Arn"]},
                "Description": f"ARN of {role_name}",
                "Export": {"Name": {"Fn::Sub": f"${{AWS::StackName}}-{logical_output}"}},
            }
            if role_name == "CohesityInstanceRole":
                output_entry["Condition"] = "RunningCE"
            outputs[logical_output] = output_entry

            if role_name == "CohesityInstanceRole":
                outputs["CohesityInstanceProfileName"] = {
                    "Value": {"Ref": "CohesityInstanceProfile"},
                    "Description": "Instance profile for Cohesity EC2 instances (CE account only)",
                    "Condition": "RunningCE",
                    "Export": {
                        "Name": {"Fn::Sub": "${AWS::StackName}-CohesityInstanceProfileName"}
                    },
                }

        # Auto-generate CohesityPermissionsBoundary when no ARN is supplied.
        if use_permissions_boundary and not boundary_arn:
            _IAM_MUTATIVE_ROLE = [
                "iam:AttachRolePolicy",
                "iam:DeleteRole",
                "iam:DeleteRolePolicy",
                "iam:PassRole",
                "iam:PutRolePolicy",
            ]
            _IAM_CREATE_ROLE = ["iam:CreateRole"]
            _IAM_INSTANCE_PROFILE = ["iam:AddRoleToInstanceProfile"]
            _IAM_SCOPED_IN_BOUNDARY = set(
                _IAM_MUTATIVE_ROLE + _IAM_CREATE_ROLE + _IAM_INSTANCE_PROFILE
            )

            # Collect all actions used across every role/policy, excluding the
            # mutative IAM actions that get their own scoped statements below.
            _all_used_actions: set[str] = {
                act
                for _pols in role_to_policies.values()
                for _svcs in _pols.values()
                for _acts in _svcs.values()
                for act in _acts
            }
            _non_scoped_actions = _all_used_actions - _IAM_SCOPED_IN_BOUNDARY

            # Compress the action list to stay within the 6,144-byte managed
            # policy size limit.  Non-IAM services are collapsed to a single
            # "service:*" wildcard per service (safe for a permissions boundary
            # because the identity policies remain the fine-grained control).
            # IAM read-only/non-escalation actions stay explicit at Resource:*;
            # dangerous IAM mutatives are handled in the scoped statements below.
            _non_iam_svcs: set[str] = {
                a.split(":")[0]
                for a in _non_scoped_actions
                if not a.startswith("iam:")
            }
            _iam_readonly = sorted(a for a in _non_scoped_actions if a.startswith("iam:"))
            _boundary_action_list: list[str] = sorted(
                {f"{svc}:*" for svc in _non_iam_svcs}
            ) + _iam_readonly

            _boundary_stmts: list[dict] = [
                {
                    "Sid": "AllGrantedPermissions",
                    "Effect": "Allow",
                    "Action": _boundary_action_list,
                    "Resource": "*",
                },
                {
                    "Sid": "IAMCreateRoleScoped",
                    "Effect": "Allow",
                    "Action": _IAM_CREATE_ROLE,
                    "Resource": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/${RoleNamePrefix}*"},
                    "Condition": {
                        "StringEquals": {
                            "iam:PermissionsBoundary": {
                                "Fn::Sub": "arn:aws:iam::${AWS::AccountId}:policy/${RoleNamePrefix}PermissionsBoundary"
                            }
                        }
                    },
                },
                {
                    "Sid": "IAMMutativeRoleScoped",
                    "Effect": "Allow",
                    "Action": _IAM_MUTATIVE_ROLE,
                    "Resource": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/${RoleNamePrefix}*"},
                },
                {
                    "Sid": "IAMInstanceProfileScoped",
                    "Effect": "Allow",
                    "Action": _IAM_INSTANCE_PROFILE,
                    "Resource": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:instance-profile/${RoleNamePrefix}*"},
                },
            ]
            # Only include the scoped IAM statements if those actions are actually
            # in the permission set for this deployment.
            _boundary_stmts = [
                s for s in _boundary_stmts
                if s["Sid"] == "AllGrantedPermissions"
                or any(a in _all_used_actions for a in s["Action"])
            ]
            cft_resources["CohesityPermissionsBoundary"] = {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": {
                        "Fn::Sub": "${RoleNamePrefix}PermissionsBoundary"
                    },
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": _boundary_stmts,
                    },
                },
            }

        parameters: dict[str, Any] = {
            "RoleNamePrefix": {
                "Type": "String",
                "Default": role_name_prefix,
                "Description": "Prefix for all Cohesity IAM role, policy, and instance profile names (e.g. 'Cohesity' produces CohesitySourceRegistrationRole)",
                "AllowedPattern": "[A-Za-z][A-Za-z0-9]*",
                "ConstraintDescription": "Must start with a letter and contain only alphanumeric characters",
            },
            "CohesityAccountId": {
                "Type": "String",
                "Default": cohesity_account_id,
                "Description": "AWS account ID where Cohesity Cloud Edition is running (used in role trust policies)",
            },
        }

        if boundary_arn and use_permissions_boundary:
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
            "Conditions": {
                # RunningCE: true when this CFT is deployed in the same account as Cohesity CE.
                # CohesityInstanceRole is only created in the CE account.
                # When deployed in a protected account, the roles trust the CE account via
                # the CohesityAccountId parameter and no InstanceRole is created here.
                "RunningCE": {
                    "Fn::Equals": [{"Ref": "CohesityAccountId"}, {"Ref": "AWS::AccountId"}]
                }
            },
            "Parameters": parameters,
            "Resources": cft_resources,
            "Outputs": outputs,
        }


def _chunk_statements(statements: list, limit: int) -> list[list]:
    """Bin-pack *statements* into groups so each group's policy doc stays under *limit* bytes."""
    empty_doc = len(_json.dumps({"Version": "2012-10-17", "Statement": []}).encode())
    chunks: list[list] = []
    current: list = []
    current_size = empty_doc
    for stmt in statements:
        # Each additional statement costs its own JSON plus a comma separator
        stmt_bytes = len(_json.dumps(stmt).encode()) + (1 if current else 0)
        if current and current_size + stmt_bytes > limit:
            chunks.append(current)
            current = [stmt]
            current_size = empty_doc + len(_json.dumps(stmt).encode())
        else:
            current.append(stmt)
            current_size += stmt_bytes
    if current:
        chunks.append(current)
    return chunks


def _build_trust_policy(
    role_name: str,
    cohesity_account_id: str,
    external_id: str = "",
) -> dict[str, Any]:
    """Build a role trust policy.

    All roles except CohesityInstanceRole trust the CE account root so that
    Cohesity's instance role (in the CE account) can assume them cross-account.
    The CohesityInstanceRole trusts the EC2 service and is only created when
    deploying in the CE account (see RunningCE condition).

    When ``external_id`` is set it is added as an ``sts:ExternalId`` condition
    on the ``sts:AssumeRole`` statement for all account-principal roles, which
    prevents confused-deputy attacks across shared tenants.
    """
    if role_name == "CohesityInstanceRole":
        principal: Any = {"Service": "ec2.amazonaws.com"}
    elif role_name == "CohesityBackupS3StagingRole":
        # RDS assumes this role directly to read/write the S3 staging bucket
        # during snapshot exports and S3-based restores. Cohesity passes the
        # role ARN to the RDS API; RDS itself does the assuming.
        principal = {"Service": "rds.amazonaws.com"}
    else:
        # Reference the CohesityAccountId CFT parameter so the template is
        # portable — override the parameter at deploy time for cross-account use.
        principal = {"AWS": {"Fn::Sub": "arn:aws:iam::${CohesityAccountId}:root"}}

    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "sts:AssumeRole",
    }

    # Add sts:ExternalId condition for account-principal roles when configured.
    # Service principals (EC2, RDS) do not support ExternalId in AssumeRole.
    if external_id and role_name not in ("CohesityInstanceRole", "CohesityBackupS3StagingRole"):
        statement["Condition"] = {
            "StringEquals": {"sts:ExternalId": external_id}
        }

    return {
        "Version": "2012-10-17",
        "Statement": [statement],
    }


def _conditions_key(rule: dict) -> str:
    """Stable string key for a rule's conditions dict (empty string if no conditions)."""
    cond = rule.get("conditions")
    return _json.dumps(cond, sort_keys=True) if cond else ""


def _build_statements(
    perms_by_service: dict[str, list[str]],
    resource_scoping: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build CFT IAM statements from permissions grouped by service.

    Groups actions by (resource, conditions) so that actions with the same resource
    but different condition blocks (e.g. glue:CreateJob vs glue:DeleteJob) are emitted
    as separate statements rather than being merged under the first action's conditions.
    """
    statements: list[dict[str, Any]] = []

    for service, actions in perms_by_service.items():
        scoped: dict[tuple[str, str], list[str]] = {}
        unscoped: list[str] = []

        for action in sorted(actions):
            rule = resource_scoping.get(action)
            if rule:
                resource = rule.get("resource", "*")
                rkey = _resource_key(resource)
                ckey = _conditions_key(rule)
                scoped.setdefault((rkey, ckey), []).append(action)
            else:
                unscoped.append(action)

        for (resource_key, _ckey), acts in scoped.items():
            resource = _parse_resource_key(resource_key)
            rule = resource_scoping.get(acts[0], {})
            conditions = rule.get("conditions")
            # Sanitize service name for Sid (must be alphanumeric only)
            sid_service = service.upper().replace("-", "").replace("_", "")
            stmt: dict[str, Any] = {
                "Sid": f"{sid_service}Scoped{len(statements)}",
                "Effect": "Allow",
                "Action": sorted(acts),
                "Resource": _maybe_sub(resource),
            }
            if conditions:
                stmt["Condition"] = conditions
            statements.append(stmt)

        if unscoped:
            sid_service = service.upper().replace("-", "").replace("_", "")
            statements.append({
                "Sid": f"{sid_service}ReadOnly{len(statements)}",
                "Effect": "Allow",
                "Action": sorted(unscoped),
                "Resource": "*",
            })

    return statements


def _maybe_sub(resource: Any) -> Any:
    """Wrap resource ARNs containing CFN pseudo-params in Fn::Sub for portability."""
    if isinstance(resource, str) and "${" in resource:
        return {"Fn::Sub": resource}
    if isinstance(resource, list):
        return [_maybe_sub(r) for r in resource]
    return resource


def _resource_key(resource: Any) -> str:
    if isinstance(resource, list):
        return "||".join(sorted(resource))
    return str(resource)


def _parse_resource_key(key: str) -> Any:
    if "||" in key:
        return key.split("||")
    return key


def _build_deny_statements() -> list[dict[str, Any]]:
    """Return Deny statements that protect permissions boundaries from removal.

    These are appended to CohesitySourceRegistrationRole when use_permissions_boundary
    is true and iam_role_management is selected.  Without them an attacker with the
    role's credentials could strip the boundary and escalate to the full Allow set.
    """
    return [
        {
            "Sid": "DenyBoundaryRemoval",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteRolePermissionsBoundary",
                "iam:PutRolePermissionsBoundary",
            ],
            "Resource": {
                "Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/${RoleNamePrefix}*"
            },
        }
    ]
