"""IAM Policy generator - produces minimal IAM policy JSON from resolved permissions."""

from typing import Any


_SERVICE_SIDS = {
    "ec2": "EC2Operations",
    "rds": "RDSOperations",
    "s3": "S3Operations",
    "glacier": "GlacierOperations",
    "dynamodb": "DynamoDBOperations",
    "iam": "IAMRoleOperations",
    "ssm": "SSMOperations",
    "cloudformation": "CloudFormationOperations",
    "kms": "KMSOperations",
    "sts": "STSOperations",
}


class PolicyGenerator:
    """Generates raw IAM policy documents from resolved permission data."""

    def generate(
        self, permissions: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a minimal IAM policy document.

        Args:
            permissions: Output from FeatureDetector.resolve_permissions().
            config: Customer configuration dict.

        Returns:
            IAM policy document (dict, ready to serialise as JSON).
        """
        by_service = permissions.get("permissions_by_service", {})
        resource_scoping = permissions.get("resource_scoping", {})

        statements: list[dict[str, Any]] = []

        for service, actions in by_service.items():
            if not actions:
                continue

            scoped_actions: dict[tuple, list[str]] = {}
            unscoped_actions: list[str] = []

            for action in sorted(actions):
                rule = resource_scoping.get(action)
                if rule:
                    resource = rule.get("resource", "*")
                    conditions = rule.get("conditions")
                    resource_key = (
                        _normalise_resource_key(resource),
                        _normalise_conditions_key(conditions),
                    )
                    scoped_actions.setdefault(resource_key, []).append(action)
                else:
                    unscoped_actions.append(action)

            for (resource_key, conditions_key), acts in scoped_actions.items():
                resource = _denormalise_resource(resource_key)
                conditions = _denormalise_conditions(conditions_key)
                stmt: dict[str, Any] = {
                    "Sid": f"{_SERVICE_SIDS.get(service, service.capitalize())}Scoped",
                    "Effect": "Allow",
                    "Action": acts,
                    "Resource": resource,
                }
                if conditions:
                    stmt["Condition"] = conditions
                statements.append(stmt)

            if unscoped_actions:
                stmt = {
                    "Sid": _SERVICE_SIDS.get(service, service.capitalize()),
                    "Effect": "Allow",
                    "Action": sorted(unscoped_actions),
                    "Resource": "*",
                }
                statements.append(stmt)

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }


def _normalise_resource_key(resource: Any) -> str:
    if isinstance(resource, list):
        return "|".join(sorted(resource))
    return str(resource)


def _normalise_conditions_key(conditions: Any) -> str:
    if not conditions:
        return ""
    import json
    return json.dumps(conditions, sort_keys=True)


def _denormalise_resource(resource_key: str) -> Any:
    if "|" in resource_key:
        return resource_key.split("|")
    return resource_key


def _denormalise_conditions(conditions_key: str) -> Any:
    if not conditions_key:
        return None
    import json
    return json.loads(conditions_key)
