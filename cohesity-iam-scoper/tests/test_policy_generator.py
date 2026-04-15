"""Tests for the policy generator."""

import json
import pytest

from cohesity_iam_scoper.generators.cft_generator import CFTGenerator
from cohesity_iam_scoper.generators.policy_generator import PolicyGenerator
from cohesity_iam_scoper.mappers.feature_detector import FeatureDetector
from cohesity_iam_scoper.mappers.permission_map import PermissionMapper


SAMPLE_CONFIG = {
    "version": "1.0",
    "aws": {
        "account_id": "123456789012",
        "regions": ["us-east-1"],
        "tag_key": "CohesityManaged",
        "tag_value": "true",
    },
    "selected_features": ["source_registration_aws", "ec2_vm_backup", "s3_archive"],
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
        "use_tagging_conditions": True,
    },
    "rds": {"snapshot_prefix": "cohesity-", "allowed_engines": []},
    "iam": {
        "role_name_prefix": "Cohesity",
        "use_permissions_boundary": False,
        "permissions_boundary_arn": "",
    },
    "output": {"format": "iam-policy", "output_file": "policy.json"},
}


@pytest.fixture()
def permissions():
    mapper = PermissionMapper()
    detector = FeatureDetector(mapper)
    return detector.resolve_permissions(SAMPLE_CONFIG)


class TestPolicyGenerator:
    def test_generates_valid_json(self, permissions):
        gen = PolicyGenerator()
        policy = gen.generate(permissions, SAMPLE_CONFIG)
        # Should be serialisable without error
        serialised = json.dumps(policy)
        assert len(serialised) > 0

    def test_policy_has_version(self, permissions):
        gen = PolicyGenerator()
        policy = gen.generate(permissions, SAMPLE_CONFIG)
        assert policy.get("Version") == "2012-10-17"

    def test_policy_has_statements(self, permissions):
        gen = PolicyGenerator()
        policy = gen.generate(permissions, SAMPLE_CONFIG)
        assert isinstance(policy.get("Statement"), list)
        assert len(policy["Statement"]) > 0

    def test_statements_have_required_keys(self, permissions):
        gen = PolicyGenerator()
        policy = gen.generate(permissions, SAMPLE_CONFIG)
        for stmt in policy["Statement"]:
            assert "Effect" in stmt
            assert "Action" in stmt
            assert "Resource" in stmt
            assert stmt["Effect"] == "Allow"

    def test_permissions_count(self, permissions):
        assert permissions["total_count"] > 0

    def test_permissions_by_service_grouped(self, permissions):
        by_service = permissions["permissions_by_service"]
        assert "ec2" in by_service
        assert "s3" in by_service

    def test_resource_scoping_present(self, permissions):
        scoping = permissions["resource_scoping"]
        assert "ec2:CreateSnapshot" in scoping

    def test_s3_resources_use_bucket_pattern(self, permissions):
        scoping = permissions["resource_scoping"]
        s3_put = scoping.get("s3:PutObject", {})
        resource = s3_put.get("resource", "")
        if isinstance(resource, list):
            assert any("cohesity-*" in r for r in resource)
        else:
            assert "cohesity-*" in resource


# ---------------------------------------------------------------------------
# Phase 5 — CFT-level and scoping-level tests for new scoped behaviors
# ---------------------------------------------------------------------------

FULL_CONFIG = {
    "version": "2.0",
    "aws": {
        "account_id": "123456789012",
        "regions": ["us-east-1"],
        "tag_key": "CohesityManaged",
        "tag_value": "true",
    },
    "selected_features": [
        "source_registration_aws",
        "ec2_vm_backup",
        "s3_protection",
        "dynamodb_backup",
        "kms_encryption",
    ],
    "s3": {
        "bucket_pattern": "cohesity-*",
        "existing_buckets": [],
        "allow_bucket_creation": True,
        "kms_encryption": True,
        "kms_key_arn": "",
    },
    "ec2": {
        "vpc_ids": [],
        "subnet_ids": [],
        "instance_types": [],
        "use_tagging_conditions": True,
        "security_group_ids": [],
        "ami_owner_account_ids": [],
    },
    "rds": {"snapshot_prefix": "cohesity-", "allowed_engines": []},
    "iam": {
        "role_name_prefix": "Cohesity",
        "use_permissions_boundary": False,
        "permissions_boundary_arn": "",
    },
    "kms": {"key_arns": [], "enforce_via_service": True},
    "dynamodb": {"table_name_pattern": "", "staging_bucket_pattern": ""},
    "redshift": {"cluster_identifiers": [], "db_users": []},
    "glue": {"job_name_prefix": ""},
    "output": {"format": "cft", "output_file": "scoped-cft.json"},
}


@pytest.fixture()
def full_permissions():
    mapper = PermissionMapper()
    detector = FeatureDetector(mapper)
    return detector.resolve_permissions(FULL_CONFIG)


def _get_cft_statements(cft: dict) -> list[dict]:
    """Flatten all IAM statements from every inline policy and managed policy in the CFT."""
    stmts: list[dict] = []
    for resource in cft.get("Resources", {}).values():
        rtype = resource.get("Type", "")
        props = resource.get("Properties", {})
        if rtype == "AWS::IAM::ManagedPolicy":
            doc = props.get("PolicyDocument", {})
            stmts.extend(doc.get("Statement", []))
        elif rtype == "AWS::IAM::Role":
            for pol in props.get("Policies", []):
                doc = pol.get("PolicyDocument", {})
                stmts.extend(doc.get("Statement", []))
    return stmts


class TestCFTGenerator:
    @pytest.fixture(autouse=True)
    def _build_cft(self, full_permissions):
        self._permissions = full_permissions
        self._cft = CFTGenerator().generate(full_permissions, FULL_CONFIG)
        self._stmts = _get_cft_statements(self._cft)

    def test_glue_statements_have_condition_block(self):
        """Glue actions in dynamodb_backup must carry tag conditions when use_tagging_conditions=True."""
        glue_stmts = [
            s for s in self._stmts
            if any(
                (a if isinstance(a, str) else "").startswith("glue:")
                for a in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action", "")])
            )
        ]
        assert glue_stmts, "No Glue statements found in generated CFT"
        assert any("Condition" in s for s in glue_stmts), (
            "At least one Glue statement must have a Condition block "
            "(see plan Item 12 / Remediation 1A)"
        )

    def test_s3_put_bucket_policy_is_bucket_scoped(self):
        """s3:PutBucketPolicy must be scoped to a bucket-pattern ARN, not '*'."""
        for stmt in self._stmts:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if "s3:PutBucketPolicy" in actions:
                resource = stmt.get("Resource", "*")
                resources = resource if isinstance(resource, list) else [resource]
                assert not (len(resources) == 1 and resources[0] == "*"), (
                    "s3:PutBucketPolicy must not have Resource: '*' "
                    "(see plan Item 13 / Remediation 3A)"
                )
                assert any("cohesity-" in str(r) for r in resources), (
                    "s3:PutBucketPolicy resource must match the cohesity-* bucket pattern"
                )
                return
        pytest.fail("s3:PutBucketPolicy not found in generated CFT statements")

    def test_dynamodb_data_plane_is_table_scoped(self):
        """dynamodb:BatchWriteItem must be scoped to a table-level ARN, not '*'."""
        for stmt in self._stmts:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if "dynamodb:BatchWriteItem" in actions:
                resource = stmt.get("Resource", "*")
                resource_str = json.dumps(resource)
                assert "table/" in resource_str, (
                    "dynamodb:BatchWriteItem resource must contain 'table/' "
                    "(see plan Item 17 / Remediation 3F)"
                )
                assert "*" != resource, (
                    "dynamodb:BatchWriteItem must not have bare Resource: '*'"
                )
                return
        pytest.fail("dynamodb:BatchWriteItem not found in generated CFT statements")

    def test_kms_decrypt_has_via_service_condition(self):
        """kms:Decrypt resolved scoping must include a kms:ViaService condition.

        The condition is set by _apply_customer_context() on the per-action resolved rule.
        (Note: _build_statements groups KMS actions by resource, using the first action's
        conditions for the whole group — so this test validates the feature_detector layer
        directly, which is where the ViaService condition is applied.)
        """
        scoping = self._permissions["resource_scoping"]
        decrypt_rule = scoping.get("kms:Decrypt", {})
        assert decrypt_rule, "kms:Decrypt must have a resolved scoping entry"
        conditions = decrypt_rule.get("conditions", {})
        assert conditions, (
            "kms:Decrypt must have a conditions block in resolved scoping "
            "(see plan Item 15 / Remediation 3E)"
        )
        assert "kms:ViaService" in json.dumps(conditions), (
            "kms:Decrypt conditions must include kms:ViaService"
        )
