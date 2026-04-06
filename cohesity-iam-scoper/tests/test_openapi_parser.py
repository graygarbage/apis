"""Tests for the OpenAPI parser."""

import os
import tempfile

import pytest
import yaml

from cohesity_iam_scoper.parsers.openapi_parser import OpenAPIParser


MINIMAL_V2_SPEC = {
    "basePath": "/v2",
    "definitions": {},
    "paths": {
        "/data-protect/protection-groups": {
            "get": {
                "operationId": "GetProtectionGroups",
                "summary": "Get the list of Protection Groups",
                "tags": ["ProtectionGroups"],
                "parameters": [
                    {
                        "name": "environments",
                        "in": "query",
                        "type": "array",
                        "items": {
                            "enum": [
                                "kAWS", "kAWSNative", "kVMware", "kAzure",
                                "kRDSSnapshotManager"
                            ],
                            "type": "string"
                        }
                    }
                ],
                "responses": {"200": {"description": "Success"}},
            },
            "post": {
                "operationId": "CreateProtectionGroup",
                "summary": "Create a Protection Group.",
                "tags": ["ProtectionGroups"],
                "parameters": [],
                "responses": {"201": {"description": "Success"}},
            },
        },
        "/users": {
            "get": {
                "operationId": "GetUsers",
                "summary": "List all users.",
                "tags": ["Users"],
                "parameters": [],
                "responses": {"200": {"description": "Success"}},
            }
        },
        "/data-protect/external-targets": {
            "post": {
                "operationId": "CreateExternalTarget",
                "summary": "Register an external archive target (S3/Glacier/etc.)",
                "tags": ["Archive"],
                "parameters": [],
                "responses": {"201": {"description": "Success"}},
            }
        },
    },
}


@pytest.fixture()
def v2_spec_path(tmp_path):
    p = tmp_path / "cluster_v2_api.yaml"
    p.write_text(yaml.dump(MINIMAL_V2_SPEC))
    return str(p)


class TestOpenAPIParser:
    def test_parse_returns_dict(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path)
        assert isinstance(result, dict)

    def test_detects_aws_endpoints(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path, aws_only=True)
        assert result["aws_relevant_endpoints"] > 0

    def test_filters_non_aws_endpoints(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path, aws_only=True)
        endpoints = result["endpoints"]
        paths = [e["path"] for e in endpoints]
        assert "/users" not in paths

    def test_protection_groups_included(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path, aws_only=True)
        endpoints = result["endpoints"]
        paths = [e["path"] for e in endpoints]
        assert "/data-protect/protection-groups" in paths

    def test_all_endpoints_returned_when_no_filter(self, v2_spec_path):
        parser = OpenAPIParser()
        result_all = parser.parse(v2_spec_path, aws_only=False)
        result_aws = parser.parse(v2_spec_path, aws_only=True)
        assert result_all["aws_relevant_endpoints"] >= result_aws["aws_relevant_endpoints"]

    def test_spec_version_detected(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path)
        assert result["spec_version"] in ("v1", "v2")

    def test_categories_dict_present(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path)
        assert isinstance(result.get("categories"), dict)

    def test_environment_types_detected(self, v2_spec_path):
        parser = OpenAPIParser()
        result = parser.parse(v2_spec_path, aws_only=True)
        env_types = result.get("aws_environment_types_found", [])
        assert "kAWS" in env_types or "kRDSSnapshotManager" in env_types
