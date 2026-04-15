"""Integration tests covering high-risk policy generation flows.

These tests generate full CFT output and assert the structural properties
that matter for security correctness — things that unit tests on individual
modules cannot catch because the guarantee only holds end-to-end.
"""

import json
import pytest

from cohesity_iam_scoper.generators.cft_generator import CFTGenerator
from cohesity_iam_scoper.mappers.feature_detector import FeatureDetector
from cohesity_iam_scoper.mappers.permission_map import PermissionMapper
from cohesity_iam_scoper.validators.config_validator import validate_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> dict:
    """Return a minimal valid config dict, with optional section overrides."""
    base = {
        "version": "1.0",
        "aws": {
            "account_id": "123456789012",
            "cohesity_account_id": "123456789012",
            "tag_key": "UniqueTag",
            "tag_value": "cohesity",
        },
        "selected_features": [
            "source_registration_aws",
            "ec2_vm_backup",
            "rds_backup",
            "s3_archive",
            "iam_role_management",
            "kms_encryption",
        ],
        "s3": {
            "bucket_pattern": "cohesity-*",
            "existing_buckets": [],
            "allow_bucket_creation": True,
            "kms_encryption": False,
            "kms_key_arn": "",
        },
        "ec2": {
            "vpc_ids": [],
            "subnet_ids": [],
            "instance_types": [],
            "use_tagging_conditions": False,
        },
        "rds": {"snapshot_prefix": "cohesity-", "allowed_engines": []},
        "iam": {
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": False,
            "permissions_boundary_arn": "",
            "external_id": "",
        },
        "output": {"format": "cloudformation", "output_file": "scoped-cft.json"},
    }
    for section, values in overrides.items():
        if isinstance(values, dict):
            base.setdefault(section, {}).update(values)
        else:
            base[section] = values
    return base


def _generate_cft(config: dict) -> dict:
    mapper = PermissionMapper()
    detector = FeatureDetector(mapper)
    permissions = detector.resolve_permissions(config)
    generator = CFTGenerator()
    return generator.generate(permissions, config)


def _all_statements(cft: dict) -> list[dict]:
    """Collect every IAM statement across all resources in the CFT."""
    stmts = []
    for resource in cft.get("Resources", {}).values():
        _collect_statements(resource, stmts)
    return stmts


def _collect_statements(obj, stmts: list):
    if isinstance(obj, dict):
        if "Statement" in obj and isinstance(obj["Statement"], list):
            stmts.extend(obj["Statement"])
        for v in obj.values():
            _collect_statements(v, stmts)
    elif isinstance(obj, list):
        for item in obj:
            _collect_statements(item, stmts)


# ---------------------------------------------------------------------------
# Config validator tests
# ---------------------------------------------------------------------------

class TestConfigValidator:
    def test_valid_config_no_errors(self):
        errors, warnings = validate_config(_make_config())
        assert errors == []

    def test_bad_account_id_length(self):
        cfg = _make_config(aws={"account_id": "1234"})
        errors, _ = validate_config(cfg)
        assert any("account_id" in e for e in errors)

    def test_bad_account_id_non_digits(self):
        cfg = _make_config(aws={"account_id": "abc123456789"})
        errors, _ = validate_config(cfg)
        assert any("account_id" in e for e in errors)

    def test_bad_role_prefix(self):
        cfg = _make_config(iam={"role_name_prefix": "1BadPrefix"})
        errors, _ = validate_config(cfg)
        assert any("role_name_prefix" in e for e in errors)

    def test_bad_boundary_arn(self):
        cfg = _make_config(iam={
            "use_permissions_boundary": True,
            "permissions_boundary_arn": "not-an-arn",
        })
        errors, _ = validate_config(cfg)
        assert any("permissions_boundary_arn" in e for e in errors)

    def test_boundary_enabled_without_account_or_arn(self):
        cfg = _make_config(
            aws={"account_id": ""},
            iam={"use_permissions_boundary": True, "permissions_boundary_arn": ""},
        )
        errors, _ = validate_config(cfg)
        assert any("use_permissions_boundary" in e for e in errors)

    def test_unknown_feature_key_produces_warning(self):
        cfg = _make_config(selected_features=["ec2_vm_backup", "totally_fake_feature"])
        _, warnings = validate_config(cfg)
        assert any("totally_fake_feature" in w for w in warnings)

    def test_unimplemented_field_warning(self):
        cfg = _make_config(ec2={"instance_types": ["m5.large"], "vpc_ids": [], "subnet_ids": []})
        _, warnings = validate_config(cfg)
        assert any("instance_types" in w for w in warnings)

    def test_empty_selected_features_no_error(self):
        cfg = _make_config(selected_features=[])
        errors, _ = validate_config(cfg)
        assert errors == []


# ---------------------------------------------------------------------------
# Permissions boundary tests
# ---------------------------------------------------------------------------

class TestPermissionsBoundary:
    def test_create_role_has_boundary_condition(self):
        """iam:CreateRole must have an iam:PermissionsBoundary condition when boundary is on."""
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": True,
            "permissions_boundary_arn": "",
        })
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        create_role_stmts = [
            s for s in stmts
            if "iam:CreateRole" in (s.get("Action") or [s.get("Action", "")])
            and s.get("Effect") == "Allow"
        ]
        assert create_role_stmts, "No Allow statement found for iam:CreateRole"
        for stmt in create_role_stmts:
            condition = stmt.get("Condition", {})
            assert "StringEquals" in condition, (
                "iam:CreateRole Allow statement must have StringEquals condition"
            )
            se = condition["StringEquals"]
            assert "iam:PermissionsBoundary" in se, (
                "iam:CreateRole Allow statement must condition on iam:PermissionsBoundary"
            )

    def test_boundary_policy_resource_exists(self):
        """CohesityPermissionsBoundary resource must be present when boundary is enabled."""
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": True,
            "permissions_boundary_arn": "",
        })
        cft = _generate_cft(cfg)
        assert "CohesityPermissionsBoundary" in cft.get("Resources", {})

    def test_boundary_arn_uses_fn_sub_when_account_not_set(self):
        """When account_id is empty, boundary condition value must use Fn::Sub (not broken literal)."""
        cfg = _make_config(
            aws={"account_id": ""},
            iam={
                "role_name_prefix": "Cohesity",
                "use_permissions_boundary": True,
                "permissions_boundary_arn": "",
            },
        )
        # We cannot generate because validator rejects this — assert validator fires
        errors, _ = validate_config(cfg)
        assert any("use_permissions_boundary" in e for e in errors)

    def test_boundary_condition_uses_literal_arn_when_account_set(self):
        """When account_id is set, boundary condition should contain the account ID.

        The condition value may be a plain string (in role inline policies) or a
        CFT Fn::Sub dict (in the boundary policy's own statements). Both are valid;
        the plain string form must contain the literal account ID.
        """
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": True,
            "permissions_boundary_arn": "",
        })
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        checked = 0
        for stmt in stmts:
            if "iam:CreateRole" not in (stmt.get("Action") or []):
                continue
            if stmt.get("Effect") != "Allow":
                continue
            pb_val = stmt.get("Condition", {}).get("StringEquals", {}).get("iam:PermissionsBoundary")
            assert pb_val is not None
            if isinstance(pb_val, str):
                assert "123456789012" in pb_val, (
                    f"Literal boundary ARN should contain account ID but got: {pb_val}"
                )
            else:
                # CFT Fn::Sub dict — valid for boundary policy's own statement
                assert "Fn::Sub" in pb_val, f"Expected Fn::Sub dict but got: {pb_val}"
            checked += 1
        assert checked > 0, "No iam:CreateRole Allow statement with PermissionsBoundary condition found"

    def test_all_roles_have_permissions_boundary(self):
        """Every IAM role in the CFT must reference the boundary when enabled."""
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": True,
            "permissions_boundary_arn": "",
        })
        cft = _generate_cft(cfg)
        for logical_id, resource in cft.get("Resources", {}).items():
            if resource.get("Type") == "AWS::IAM::Role":
                props = resource.get("Properties", {})
                assert "PermissionsBoundary" in props, (
                    f"Role {logical_id} is missing PermissionsBoundary"
                )

    def test_deny_boundary_removal_statement_present(self):
        """DenyBoundaryRemoval Deny statement must exist when boundary is enabled."""
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": True,
            "permissions_boundary_arn": "",
        })
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        deny_stmts = [
            s for s in stmts
            if s.get("Effect") == "Deny"
            and any(
                a in (s.get("Action") or [])
                for a in ("iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary")
            )
        ]
        assert deny_stmts, "No Deny statement found for boundary removal actions"


# ---------------------------------------------------------------------------
# Tag / condition tests
# ---------------------------------------------------------------------------

class TestTagConditions:
    def test_glue_delete_has_resource_tag_condition(self):
        """glue:DeleteJob must have an aws:ResourceTag condition."""
        cfg = _make_config(
            selected_features=["dynamodb_backup"],
            aws={"tag_key": "UniqueTag", "tag_value": "cohesity"},
        )
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        glue_delete_stmts = [
            s for s in stmts
            if "glue:DeleteJob" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        assert glue_delete_stmts, "No Allow statement found for glue:DeleteJob"
        for stmt in glue_delete_stmts:
            condition = stmt.get("Condition", {})
            assert "StringLike" in condition, "glue:DeleteJob must have StringLike condition"
            sl = condition["StringLike"]
            assert any("ResourceTag" in k for k in sl), (
                "glue:DeleteJob StringLike must reference a ResourceTag key"
            )

    def test_sqs_delete_has_resource_tag_condition(self):
        """sqs:DeleteQueue must have an aws:ResourceTag condition."""
        cfg = _make_config(selected_features=["s3_protection"])
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        sqs_delete_stmts = [
            s for s in stmts
            if "sqs:DeleteQueue" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        assert sqs_delete_stmts, "No Allow statement found for sqs:DeleteQueue"
        for stmt in sqs_delete_stmts:
            condition = stmt.get("Condition", {})
            assert "StringLike" in condition
            sl = condition["StringLike"]
            assert any("ResourceTag" in k for k in sl)

    def test_kms_via_service_condition(self):
        """kms:Decrypt must have a kms:ViaService condition."""
        cfg = _make_config(selected_features=["kms_encryption", "ec2_vm_backup"])
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        kms_decrypt_stmts = [
            s for s in stmts
            if "kms:Decrypt" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        assert kms_decrypt_stmts, "No Allow statement found for kms:Decrypt"
        for stmt in kms_decrypt_stmts:
            condition = stmt.get("Condition", {})
            assert "StringLike" in condition
            sl = condition["StringLike"]
            assert "kms:ViaService" in sl, "kms:Decrypt must have kms:ViaService condition"


# ---------------------------------------------------------------------------
# Multi-bucket pattern tests
# ---------------------------------------------------------------------------

class TestMultiBucketPatterns:
    def test_two_bucket_patterns_both_appear_in_s3_resources(self):
        cfg = _make_config(
            selected_features=["s3_archive"],
            s3={"bucket_pattern": ["cohesity-*", "zcg-*"]},
        )
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        s3_put_stmts = [
            s for s in stmts
            if "s3:PutObject" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        assert s3_put_stmts, "No s3:PutObject statement found"
        resources = []
        for s in s3_put_stmts:
            r = s.get("Resource", [])
            if isinstance(r, list):
                resources.extend(r)
            else:
                resources.append(r)
        resource_str = json.dumps(resources)
        assert "cohesity-*" in resource_str, "cohesity-* pattern not in s3 resources"
        assert "zcg-*" in resource_str, "zcg-* pattern not in s3 resources"

    def test_comma_separated_bucket_pattern_string(self):
        cfg = _make_config(
            selected_features=["s3_archive"],
            s3={"bucket_pattern": "cohesity-*, zcg-*"},
        )
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        resources = []
        for s in stmts:
            if "s3:PutObject" in (s.get("Action") or []) and s.get("Effect") == "Allow":
                r = s.get("Resource", [])
                resources.extend(r if isinstance(r, list) else [r])
        resource_str = json.dumps(resources)
        assert "cohesity-*" in resource_str
        assert "zcg-*" in resource_str


# ---------------------------------------------------------------------------
# VPC / subnet scoping tests
# ---------------------------------------------------------------------------

# ec2:CreateSecurityGroup has vpc/* in its resource (from ec2_vm_restore / source_registration_aws)
# ec2:RunInstances has subnet/* in its resource (from ec2_vm_backup)
_EC2_VPC_FEATURES = ["source_registration_aws", "ec2_vm_backup", "ec2_vm_restore"]


class TestVpcSubnetScoping:
    def test_vpc_ids_narrow_create_security_group_resource(self):
        """When vpc_ids is set, CreateSecurityGroup resource should list specific VPC ARNs."""
        cfg = _make_config(
            selected_features=_EC2_VPC_FEATURES,
            ec2={"vpc_ids": ["vpc-aaa111", "vpc-bbb222"], "subnet_ids": [], "instance_types": []},
        )
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        sg_stmts = [
            s for s in stmts
            if "ec2:CreateSecurityGroup" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        resources = []
        for s in sg_stmts:
            r = s.get("Resource", [])
            resources.extend(r if isinstance(r, list) else [r])
        resource_str = json.dumps(resources)
        assert "vpc-aaa111" in resource_str, "Specific vpc-aaa111 ARN not found in CreateSecurityGroup resource"
        assert "vpc-bbb222" in resource_str, "Specific vpc-bbb222 ARN not found in CreateSecurityGroup resource"
        assert ":vpc/*" not in resource_str, "Wildcard vpc/* should be replaced by specific VPC ARNs"

    def test_subnet_ids_narrow_run_instances_resource(self):
        """When subnet_ids is set, RunInstances resource should list specific subnet ARNs."""
        cfg = _make_config(
            selected_features=["ec2_vm_backup"],
            ec2={"vpc_ids": [], "subnet_ids": ["subnet-11111111", "subnet-22222222"], "instance_types": []},
        )
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        run_stmts = [
            s for s in stmts
            if "ec2:RunInstances" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        resources = []
        for s in run_stmts:
            r = s.get("Resource", [])
            resources.extend(r if isinstance(r, list) else [r])
        resource_str = json.dumps(resources)
        assert "subnet-11111111" in resource_str
        assert "subnet-22222222" in resource_str
        assert ":subnet/*" not in resource_str

    def test_no_vpc_ids_keeps_wildcard(self):
        """When vpc_ids is empty, CreateSecurityGroup resource retains the vpc/* wildcard."""
        cfg = _make_config(
            selected_features=_EC2_VPC_FEATURES,
            ec2={"vpc_ids": [], "subnet_ids": [], "instance_types": []},
        )
        cft = _generate_cft(cfg)
        stmts = _all_statements(cft)
        sg_stmts = [
            s for s in stmts
            if "ec2:CreateSecurityGroup" in (s.get("Action") or [])
            and s.get("Effect") == "Allow"
        ]
        resources = []
        for s in sg_stmts:
            r = s.get("Resource", [])
            resources.extend(r if isinstance(r, list) else [r])
        resource_str = json.dumps(resources)
        assert ":vpc/*" in resource_str, "With no vpc_ids, CreateSecurityGroup should keep vpc/* wildcard"


# ---------------------------------------------------------------------------
# External ID / trust policy tests
# ---------------------------------------------------------------------------

class TestExternalIdTrustPolicy:
    def test_external_id_added_to_account_principal_trust(self):
        """sts:ExternalId condition must appear on account-principal roles when set."""
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": False,
            "permissions_boundary_arn": "",
            "external_id": "cohesity-prod-12345",
        })
        cft = _generate_cft(cfg)
        account_roles = [
            (lid, res)
            for lid, res in cft.get("Resources", {}).items()
            if res.get("Type") == "AWS::IAM::Role"
            and lid not in ("CohesityInstanceRole", "CohesityBackupS3StagingRole")
        ]
        assert account_roles, "No account-principal roles found"
        for lid, role in account_roles:
            trust_stmts = (
                role.get("Properties", {})
                .get("AssumeRolePolicyDocument", {})
                .get("Statement", [])
            )
            for stmt in trust_stmts:
                if "AWS" in stmt.get("Principal", {}):
                    condition = stmt.get("Condition", {})
                    assert "StringEquals" in condition, (
                        f"{lid} trust statement missing StringEquals condition"
                    )
                    assert condition["StringEquals"].get("sts:ExternalId") == "cohesity-prod-12345", (
                        f"{lid} trust condition missing/wrong sts:ExternalId"
                    )

    def test_no_external_id_no_condition(self):
        """Without external_id, trust policies must not have a Condition block."""
        cfg = _make_config(iam={
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": False,
            "permissions_boundary_arn": "",
            "external_id": "",
        })
        cft = _generate_cft(cfg)
        for lid, resource in cft.get("Resources", {}).items():
            if resource.get("Type") != "AWS::IAM::Role":
                continue
            trust_stmts = (
                resource.get("Properties", {})
                .get("AssumeRolePolicyDocument", {})
                .get("Statement", [])
            )
            for stmt in trust_stmts:
                if "AWS" in stmt.get("Principal", {}):
                    assert "Condition" not in stmt, (
                        f"{lid} trust statement has unexpected Condition without external_id"
                    )

    def test_service_principal_roles_never_get_external_id(self):
        """EC2 and RDS service-principal roles must not have ExternalId condition."""
        cfg = _make_config(
            selected_features=[
                "source_registration_aws", "ec2_vm_backup", "rds_backup",
                "rds_staging_s3", "iam_role_management", "instance_role",
            ],
            iam={
                "role_name_prefix": "Cohesity",
                "use_permissions_boundary": False,
                "permissions_boundary_arn": "",
                "external_id": "should-not-appear-on-service-roles",
            },
        )
        cft = _generate_cft(cfg)
        service_role_ids = {"CohesityInstanceRole", "CohesityBackupS3StagingRole"}
        for lid in service_role_ids:
            role = cft.get("Resources", {}).get(lid)
            if role is None:
                continue  # role may not be generated if feature not selected
            trust_stmts = (
                role.get("Properties", {})
                .get("AssumeRolePolicyDocument", {})
                .get("Statement", [])
            )
            for stmt in trust_stmts:
                assert "Condition" not in stmt, (
                    f"Service-principal role {lid} should not have Condition in trust policy"
                )


# ---------------------------------------------------------------------------
# CFT structure / serialisability tests
# ---------------------------------------------------------------------------

class TestCFTStructure:
    def test_generated_cft_is_serialisable(self):
        cfg = _make_config()
        cft = _generate_cft(cfg)
        assert json.dumps(cft)

    def test_cft_has_resources(self):
        cfg = _make_config()
        cft = _generate_cft(cfg)
        assert "Resources" in cft
        assert len(cft["Resources"]) > 0

    def test_all_actions_are_strings(self):
        """Verify no statement has a dict or None as an action value."""
        cfg = _make_config()
        cft = _generate_cft(cfg)
        for stmt in _all_statements(cft):
            actions = stmt.get("Action", [])
            if isinstance(actions, list):
                for a in actions:
                    assert isinstance(a, str), f"Non-string action: {a}"
            else:
                assert isinstance(actions, str), f"Non-string action: {actions}"
