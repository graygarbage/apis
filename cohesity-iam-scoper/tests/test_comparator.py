"""Tests for the policy comparator."""

import json
import pytest

from cohesity_iam_scoper.generators.comparison import PolicyComparator


BROAD_CFT = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": "BroadRole",
                "AssumeRolePolicyDocument": {},
                "Policies": [
                    {
                        "PolicyName": "BroadPolicy",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:CreateRole",
                                        "iam:DeleteRole",
                                        "s3:DeleteObject",
                                        "s3:GetObject",
                                        "ec2:TerminateInstances",
                                        "ec2:DescribeInstances",
                                    ],
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                ],
            },
        }
    },
}

SCOPED_CFT = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": "ScopedRole",
                "AssumeRolePolicyDocument": {},
                "Policies": [
                    {
                        "PolicyName": "ScopedPolicy",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["ec2:DescribeInstances", "s3:GetObject"],
                                    "Resource": "*",
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:DeleteObject",
                                    "Resource": "arn:aws:s3:::cohesity-*/*",
                                },
                            ]
                        },
                    }
                ],
            },
        }
    },
}


@pytest.fixture()
def broad_cft_path(tmp_path):
    p = tmp_path / "broad.json"
    p.write_text(json.dumps(BROAD_CFT))
    return str(p)


@pytest.fixture()
def scoped_cft_path(tmp_path):
    p = tmp_path / "scoped.json"
    p.write_text(json.dumps(SCOPED_CFT))
    return str(p)


class TestPolicyComparator:
    def test_compare_returns_report(self, broad_cft_path, scoped_cft_path):
        comparator = PolicyComparator()
        report = comparator.compare(broad_cft_path, scoped_cft_path)
        assert "current" in report
        assert "scoped" in report
        assert "delta" in report

    def test_scoped_has_fewer_permissions(self, broad_cft_path, scoped_cft_path):
        comparator = PolicyComparator()
        report = comparator.compare(broad_cft_path, scoped_cft_path)
        assert report["scoped"]["total_permissions"] < report["current"]["total_permissions"]

    def test_permission_reduction_positive(self, broad_cft_path, scoped_cft_path):
        comparator = PolicyComparator()
        report = comparator.compare(broad_cft_path, scoped_cft_path)
        assert report["delta"]["permission_reduction_pct"] > 0

    def test_removed_permissions_listed(self, broad_cft_path, scoped_cft_path):
        comparator = PolicyComparator()
        report = comparator.compare(broad_cft_path, scoped_cft_path)
        removed = report["delta"]["removed_permissions"]
        assert "iam:CreateRole" in removed or "iam:DeleteRole" in removed

    def test_file_paths_in_report(self, broad_cft_path, scoped_cft_path):
        comparator = PolicyComparator()
        report = comparator.compare(broad_cft_path, scoped_cft_path)
        assert report["current_file"] == broad_cft_path
        assert report["scoped_file"] == scoped_cft_path
