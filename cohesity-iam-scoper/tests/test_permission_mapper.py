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
