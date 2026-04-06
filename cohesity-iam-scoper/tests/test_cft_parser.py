"""Tests for the CFT parser."""

import json
import os
import tempfile

import pytest

from cohesity_iam_scoper.parsers.cft_parser import CFTParser


SAMPLE_CFT = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "CohesityArchiveRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": "CohesityArchiveRole",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
                },
                "Policies": [
                    {
                        "PolicyName": "ArchivePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "S3Wildcard",
                                    "Effect": "Allow",
                                    "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
                                    "Resource": "arn:aws:s3:::*/*",
                                },
                                {
                                    "Sid": "IAMWildcard",
                                    "Effect": "Allow",
                                    "Action": "iam:CreateRole",
                                    "Resource": "*",
                                },
                            ],
                        },
                    }
                ],
            },
        }
    },
}


@pytest.fixture()
def sample_cft_path(tmp_path):
    """Write the sample CFT to a temp file."""
    p = tmp_path / "cft.json"
    p.write_text(json.dumps(SAMPLE_CFT))
    return str(p)


class TestCFTParser:
    def test_parses_roles(self, sample_cft_path):
        parser = CFTParser()
        result = parser.analyze(sample_cft_path)
        assert result["summary"]["total_roles"] == 1
        assert result["roles"][0]["resource_name"] == "CohesityArchiveRole"

    def test_counts_permissions(self, sample_cft_path):
        parser = CFTParser()
        result = parser.analyze(sample_cft_path)
        assert result["summary"]["total_permissions"] == 4

    def test_detects_wildcard_resources(self, sample_cft_path):
        parser = CFTParser()
        result = parser.analyze(sample_cft_path)
        assert result["summary"]["wildcard_resource_permissions"] > 0

    def test_identifies_high_risk_actions(self, sample_cft_path):
        parser = CFTParser()
        result = parser.analyze(sample_cft_path)
        high_risk = [f for f in result["findings"] if f["severity"] in ("HIGH", "CRITICAL")]
        assert len(high_risk) >= 1
        actions_in_findings = [f.get("action") for f in high_risk]
        assert "iam:CreateRole" in actions_in_findings

    def test_file_path_in_result(self, sample_cft_path):
        parser = CFTParser()
        result = parser.analyze(sample_cft_path)
        assert result["file"] == sample_cft_path

    def test_permissions_list_not_empty(self, sample_cft_path):
        parser = CFTParser()
        result = parser.analyze(sample_cft_path)
        assert len(result["permissions"]) > 0

    def test_non_allow_statements_skipped(self, tmp_path):
        cft = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "TestRole",
                        "AssumeRolePolicyDocument": {},
                        "Policies": [
                            {
                                "PolicyName": "DenyPolicy",
                                "PolicyDocument": {
                                    "Statement": [
                                        {
                                            "Effect": "Deny",
                                            "Action": "s3:DeleteBucket",
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
        p = tmp_path / "deny_cft.json"
        p.write_text(json.dumps(cft))
        parser = CFTParser()
        result = parser.analyze(str(p))
        assert result["summary"]["total_permissions"] == 0
