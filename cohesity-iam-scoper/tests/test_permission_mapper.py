"""Tests for the permission mapper."""

import pytest

from cohesity_iam_scoper.mappers.permission_map import PermissionMapper


class TestPermissionMapper:
    @pytest.fixture(autouse=True)
    def mapper(self):
        self.mapper = PermissionMapper()

    def test_feature_keys_not_empty(self):
        assert len(self.mapper.feature_keys) > 0

    def test_ec2_backup_permissions(self):
        perms = self.mapper.get_required_permissions("ec2_vm_backup")
        assert "ec2:CreateSnapshot" in perms
        assert "ec2:DescribeInstances" in perms

    def test_rds_backup_permissions(self):
        perms = self.mapper.get_required_permissions("rds_backup")
        assert "rds:CreateDBSnapshot" in perms
        assert "rds:DescribeDBInstances" in perms

    def test_s3_archive_permissions(self):
        perms = self.mapper.get_required_permissions("s3_archive")
        assert "s3:PutObject" in perms
        assert "s3:GetObject" in perms
        assert "s3:ListBucket" in perms

    def test_unknown_feature_raises(self):
        with pytest.raises(KeyError):
            self.mapper.get_required_permissions("nonexistent_feature")

    def test_resource_scoping_exists(self):
        scoping = self.mapper.get_resource_scoping("ec2_vm_backup")
        assert "ec2:CreateSnapshot" in scoping

    def test_risk_levels_valid(self):
        valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for key in self.mapper.feature_keys:
            level = self.mapper.get_risk_level(key)
            assert level in valid_levels, f"{key} has invalid risk level: {level}"

    def test_all_permissions_deduped(self):
        perms = self.mapper.all_permissions_for_features(
            ["ec2_vm_backup", "source_registration_aws"]
        )
        assert len(perms) == len(set(perms))

    def test_cohesity_apis_not_empty_for_backup(self):
        apis = self.mapper.get_cohesity_apis("ec2_vm_backup")
        assert len(apis) > 0

    def test_features_for_environment(self):
        features = self.mapper.features_for_environment("kAWS")
        assert "ec2_vm_backup" in features or "source_registration_aws" in features

    # --- Phase 5 additions ---

    def test_iam_create_policy_absent(self):
        # Use the raw JSON required list — get_required_permissions() may fall back to
        # CFT-derived actions (from cft.json) which still carries the original permissions.
        # Items 5/6 target the aws_permission_map.json maintenance list specifically.
        feature = self.mapper.get_feature("iam_role_management")
        required = feature.get("iam_permissions", {}).get("required", [])
        assert "iam:CreatePolicy" not in required, (
            "iam:CreatePolicy must be permanently removed from iam_role_management "
            "(privilege-escalation risk — see plan Item 5 / Flag 2)"
        )

    def test_iam_update_user_absent(self):
        # Use the raw JSON required list — same reasoning as test_iam_create_policy_absent.
        feature = self.mapper.get_feature("iam_role_management")
        required = feature.get("iam_permissions", {}).get("required", [])
        assert "iam:UpdateUser" not in required, (
            "iam:UpdateUser must be removed from iam_role_management "
            "(no legitimate use for a backup product — see plan Item 6)"
        )

    def test_glue_delete_job_has_resource_tag_condition(self):
        scoping = self.mapper.get_resource_scoping("dynamodb_backup")
        entry = scoping.get("glue:DeleteJob")
        assert entry is not None, "glue:DeleteJob must have a resource_scoping entry"
        assert "aws:ResourceTag/{tag_key}" in entry.get("condition_keys", []), (
            "glue:DeleteJob must carry aws:ResourceTag/{tag_key} condition "
            "(see plan Item 1 / Remediation 1A)"
        )

    def test_sqs_delete_queue_has_resource_tag_condition(self):
        scoping = self.mapper.get_resource_scoping("s3_protection")
        entry = scoping.get("sqs:DeleteQueue")
        assert entry is not None, "sqs:DeleteQueue must have a resource_scoping entry"
        assert "aws:ResourceTag/{tag_key}" in entry.get("condition_keys", []), (
            "sqs:DeleteQueue must carry aws:ResourceTag/{tag_key} condition "
            "(see plan Item 2 / Remediation 1B)"
        )

    def test_logs_put_log_events_has_scoped_resource(self):
        scoping = self.mapper.get_resource_scoping("dynamodb_backup")
        entry = scoping.get("logs:PutLogEvents")
        assert entry is not None, "logs:PutLogEvents must have a resource_scoping entry"
        resource = entry.get("resource", "*")
        resources = resource if isinstance(resource, list) else [resource]
        assert any("log-group" in r for r in resources), (
            "logs:PutLogEvents must be scoped to specific log-group ARNs, not '*' "
            "(see plan Item 4 / Remediation 1D)"
        )
        assert not (len(resources) == 1 and resources[0] == "*"), (
            "logs:PutLogEvents resource must not be bare '*'"
        )
