"""Tests for the policy generator."""

import json
import pytest

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
