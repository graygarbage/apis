"""Permission mapper - loads and queries the aws_permission_map.json data file."""

import json
import os
from typing import Any


_DATA_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "aws_permission_map.json"
)


class PermissionMapper:
    """Loads the AWS permission map and provides feature-to-IAM lookups."""

    def __init__(self, data_file: str = _DATA_FILE) -> None:
        resolved = os.path.realpath(data_file)
        with open(resolved, "r", encoding="utf-8") as fh:
            self._map: dict[str, Any] = json.load(fh)

    @property
    def feature_keys(self) -> list[str]:
        """Return all available feature keys."""
        return list(self._map.keys())

    def get_feature(self, feature_key: str) -> dict[str, Any]:
        """Return the full feature mapping entry for *feature_key*."""
        if feature_key not in self._map:
            raise KeyError(f"Unknown feature key: '{feature_key}'")
        return self._map[feature_key]

    def get_required_permissions(self, feature_key: str) -> list[str]:
        """Return the required IAM action list for a feature."""
        feature = self.get_feature(feature_key)
        return feature.get("iam_permissions", {}).get("required", [])

    def get_resource_scoping(self, feature_key: str) -> dict[str, Any]:
        """Return resource-scoping rules for a feature."""
        feature = self.get_feature(feature_key)
        return feature.get("iam_permissions", {}).get("resource_scoping", {})

    def get_risk_level(self, feature_key: str) -> str:
        """Return the risk level for a feature."""
        return self.get_feature(feature_key).get("risk_level", "UNKNOWN")

    def get_cohesity_apis(self, feature_key: str) -> list[str]:
        """Return the Cohesity API endpoints involved in a feature."""
        return self.get_feature(feature_key).get("cohesity_apis", [])

    def features_for_environment(self, env_type: str) -> list[str]:
        """Return feature keys that include *env_type* in their environment_types."""
        return [
            key for key, val in self._map.items()
            if env_type in val.get("environment_types", [])
        ]

    def all_permissions_for_features(self, feature_keys: list[str]) -> list[str]:
        """Deduplicated union of required permissions across multiple features."""
        seen: set[str] = set()
        result: list[str] = []
        for key in feature_keys:
            for perm in self.get_required_permissions(key):
                if perm not in seen:
                    seen.add(perm)
                    result.append(perm)
        return sorted(result)
