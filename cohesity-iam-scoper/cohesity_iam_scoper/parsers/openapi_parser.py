"""OpenAPI spec parser for Cohesity v1 and v2 API specs.

Extracts AWS-relevant endpoints by filtering for environment types such as
kAWS, kEC2, kRDS, kS3, kGlacier, kDynamoDB, etc.
"""

import re
from typing import Any

import yaml


AWS_ENVIRONMENT_TYPES = {
    "kAWS",
    "kAWSNative",
    "kAwsS3",
    "kAWSSnapshotManager",
    "kRDSSnapshotManager",
    "kRDSPostgresSnapshotManager",
    "kRDSMySQLSnapshotManager",
    "kRDSMSSQLSnapshotManager",
    "kRDSOracleSnapshotManager",
    "kRDSMariaDBSnapshotManager",
    "kRDSCustomMSSQLSnapshotManager",
    "kRDSCustomOracleSnapshotManager",
    "kAuroraSnapshotManager",
    "kAuroraPostgresSnapshotManager",
    "kAuroraMySQLSnapshotManager",
    "kAwsRDSPostgresBackup",
    "kAwsRDSPostgres",
    "kAwsAuroraPostgres",
    "kAWSMySQL",
    "kAWSAuroraMySQL",
    "kAwsDynamoDB",
    "kAWSRdsOracle",
    "kAWSDocumentDB",
    "kAWSRDSPostgresDB",
    "kAWSAuroraPostgresDB",
    "kAWSRDSMSSQL",
    "kAWSRedshift",
    "kEC2Instance",
    "kRDSInstance",
    "kS3Bucket",
}

AWS_KEYWORDS = re.compile(
    r"\b(aws|kAWS|kEC2|kRDS|kS3|kGlacier|kDynamoDB|kAuror|kRedshift|"
    r"kDocumentDB|ec2|rds|s3|glacier|dynamodb|iam|cloudformation|ssm|kms|"
    r"snapshot|archive|external.?target|cloud.?spin|CloudSpin)\b",
    re.IGNORECASE,
)

AWS_TAG_GROUPS = re.compile(
    r"\b(BackupSources|ProtectionGroups|Recoveries|Archive|ExternalTargets|"
    r"DataProtect|ProtectionSources|SnapshotManager)\b",
    re.IGNORECASE,
)


def _is_aws_relevant(path: str, operation: dict[str, Any]) -> bool:
    """Return True if a path/operation is relevant to AWS deployments."""
    combined_text = path + " " + str(operation)
    if AWS_KEYWORDS.search(combined_text):
        return True
    tags = operation.get("tags", [])
    for tag in tags:
        if AWS_TAG_GROUPS.search(tag):
            return True
    return False


def _classify_operation(path: str, method: str, operation: dict[str, Any]) -> str:
    """Classify an endpoint into a Cohesity functional category."""
    text = (path + " " + operation.get("summary", "") + " " +
            operation.get("description", "")).lower()

    if "protection-group" in text or "protection_group" in text:
        return "protection_groups"
    if "recover" in text or "restore" in text:
        return "recovery"
    if "external-target" in text or "archive" in text or "vault" in text:
        return "archive_targets"
    if "source" in text and ("registration" in text or "register" in text):
        return "source_registration"
    if "snapshot" in text:
        return "snapshots"
    if "policy" in text:
        return "policies"
    if "search" in text:
        return "search"
    return "other"


class OpenAPIParser:
    """Parses Cohesity OpenAPI v1/v2 YAML specs and extracts AWS-relevant endpoints."""

    def parse(self, spec_path: str, aws_only: bool = True) -> dict[str, Any]:
        """Parse the OpenAPI spec and return a structured summary.

        Args:
            spec_path: Path to the YAML spec file.
            aws_only: If True, filter to only AWS-relevant endpoints.

        Returns:
            A dict with metadata and categorised endpoint list.
        """
        with open(spec_path, "r", encoding="utf-8") as fh:
            spec = yaml.safe_load(fh)

        base_path = spec.get("basePath", "")
        version = "v2" if "v2" in base_path or "/v2/" in str(spec_path) else "v1"

        paths = spec.get("paths", {})
        endpoints: list[dict[str, Any]] = []
        aws_env_types: set[str] = set()

        for path, path_item in paths.items():
            for method in ("get", "post", "put", "patch", "delete"):
                operation = path_item.get(method)
                if not operation:
                    continue

                if aws_only and not _is_aws_relevant(path, operation):
                    continue

                category = _classify_operation(path, method, operation)
                summary = operation.get("summary", "").strip()
                op_id = operation.get("operationId", "")
                tags = operation.get("tags", [])

                env_types = _extract_environment_types(operation, spec)
                aws_env_types.update(env_types)

                entry: dict[str, Any] = {
                    "path": path,
                    "method": method.upper(),
                    "full_path": f"{base_path}{path}",
                    "operation_id": op_id,
                    "summary": summary,
                    "tags": tags,
                    "category": category,
                    "environment_types": sorted(
                        t for t in env_types if t in AWS_ENVIRONMENT_TYPES
                    ),
                }
                endpoints.append(entry)

        categories: dict[str, list[dict]] = {}
        for ep in endpoints:
            cat = ep["category"]
            categories.setdefault(cat, []).append(ep)

        return {
            "spec_version": version,
            "base_path": base_path,
            "total_endpoints": len(paths) * 2,
            "aws_relevant_endpoints": len(endpoints),
            "aws_environment_types_found": sorted(aws_env_types & AWS_ENVIRONMENT_TYPES),
            "categories": {k: len(v) for k, v in categories.items()},
            "endpoints": endpoints,
        }


def _extract_environment_types(
    operation: dict[str, Any], spec: dict[str, Any]
) -> set[str]:
    """Walk the operation parameters and responses to find environment type enums."""
    found: set[str] = set()
    _walk_for_env_types(operation, spec, found, depth=0)
    return found


def _walk_for_env_types(
    node: Any, spec: dict[str, Any], found: set[str], depth: int
) -> None:
    """Recursively walk a YAML node to collect enum values matching env types."""
    if depth > 4:
        return
    if isinstance(node, dict):
        enum_vals = node.get("enum")
        if isinstance(enum_vals, list):
            for v in enum_vals:
                if isinstance(v, str) and v in AWS_ENVIRONMENT_TYPES:
                    found.add(v)
        for v in node.values():
            _walk_for_env_types(v, spec, found, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _walk_for_env_types(item, spec, found, depth + 1)
