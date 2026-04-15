"""CloudFormation template parser.

Extracts IAM permissions from existing CFT files, calculates risk scores,
and identifies scoping opportunities.
"""

import json
import re
from typing import Any


WILDCARD_RESOURCE_PATTERN = re.compile(r"^\*$|:\*$|/\*$")

HIGH_RISK_ACTIONS = {
    "iam:CreateRole", "iam:DeleteRole", "iam:PutRolePolicy",
    "iam:AttachRolePolicy", "iam:DetachRolePolicy",
    "iam:CreatePolicy", "iam:DeletePolicy",
    "iam:CreateUser", "iam:DeleteUser",
    "s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjectVersion",
    "ec2:TerminateInstances", "ec2:RunInstances",
    "ec2:DeleteSecurityGroup", "ec2:AuthorizeSecurityGroupIngress",
    "ssm:SendCommand",
    "cloudformation:DeleteStack", "cloudformation:UpdateStack",
    "kms:DeleteAlias", "kms:ScheduleKeyDeletion",
}

MEDIUM_RISK_ACTIONS = {
    "iam:PassRole",
    "ec2:CreateSecurityGroup", "ec2:ModifyInstanceAttribute",
    "s3:PutBucketPolicy", "s3:PutBucketAcl",
    "rds:DeleteDBInstance", "rds:DeleteDBCluster",
    "ssm:GetParameter", "ssm:GetParameters",
}


def _extract_statements(policy_doc: Any) -> list[dict]:
    """Extract Statement list from a policy document."""
    if isinstance(policy_doc, dict):
        stmts = policy_doc.get("Statement", [])
        if isinstance(stmts, list):
            return stmts
    return []


def _normalise_actions(action_field: Any) -> list[str]:
    """Return a flat list of action strings."""
    if isinstance(action_field, str):
        return [action_field]
    if isinstance(action_field, list):
        return [a for a in action_field if isinstance(a, str)]
    return []


def _normalise_resources(resource_field: Any) -> list[str]:
    """Return a flat list of resource strings."""
    if isinstance(resource_field, str):
        return [resource_field]
    if isinstance(resource_field, list):
        return [r for r in resource_field if isinstance(r, str)]
    return []


def _is_wildcard(resource: str) -> bool:
    return resource == "*" or resource.endswith(":*") or resource.endswith("/*")


def _risk_level(actions: list[str], resources: list[str]) -> str:
    """Calculate risk level for a set of actions and resources."""
    has_wildcard = any(_is_wildcard(r) for r in resources)
    action_set = {a.lower() for a in actions}
    high = any(a.lower() in {h.lower() for h in HIGH_RISK_ACTIONS} for a in actions)
    medium = any(a.lower() in {m.lower() for m in MEDIUM_RISK_ACTIONS} for a in actions)
    wildcard_action = any(a.endswith(":*") or a == "*" for a in actions)

    if wildcard_action and has_wildcard:
        return "CRITICAL"
    if high and has_wildcard:
        return "HIGH"
    if high or (medium and has_wildcard):
        return "MEDIUM"
    if has_wildcard:
        return "LOW"
    return "INFO"


class CFTParser:
    """Parses CloudFormation templates to extract and assess IAM permissions."""

    def extract_policy_actions(self, cft_path: str) -> dict[str, list[str]]:
        """Extract IAM actions grouped by 'RoleName/PolicyName' from a CFT file.

        Returns:
            dict mapping "RoleName/PolicyName" -> sorted unique action list.
            Wildcard actions (e.g. ``ssmmessages:*``) are preserved as-is.
        """
        with open(cft_path, "r", encoding="utf-8") as fh:
            cft = json.load(fh)

        result: dict[str, list[str]] = {}
        for resource_body in cft.get("Resources", {}).values():
            if resource_body.get("Type") != "AWS::IAM::Role":
                continue
            props = resource_body.get("Properties", {})
            role_name = props.get("RoleName", "")
            if not role_name:
                continue
            for policy in props.get("Policies", []):
                policy_name = policy.get("PolicyName", "")
                if not policy_name:
                    continue
                key = f"{role_name}/{policy_name}"
                actions: set[str] = set()
                for stmt in _extract_statements(policy.get("PolicyDocument", {})):
                    if stmt.get("Effect", "Allow") != "Allow":
                        continue
                    for action in _normalise_actions(stmt.get("Action", [])):
                        actions.add(action)
                result[key] = sorted(actions)

        return result

    def analyze(self, cft_path: str) -> dict[str, Any]:
        """Parse a CFT file and return a comprehensive permission analysis.

        Args:
            cft_path: Path to the CloudFormation JSON file.

        Returns:
            Analysis dict with permissions, risk findings, and scoping opportunities.
        """
        with open(cft_path, "r", encoding="utf-8") as fh:
            cft = json.load(fh)

        resources = cft.get("Resources", {})
        roles: list[dict[str, Any]] = []
        all_permissions: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        for resource_name, resource_body in resources.items():
            if resource_body.get("Type") != "AWS::IAM::Role":
                continue

            role_info: dict[str, Any] = {
                "resource_name": resource_name,
                "role_name": resource_body.get("Properties", {}).get(
                    "RoleName", resource_name
                ),
                "policies": [],
                "permission_count": 0,
            }

            props = resource_body.get("Properties", {})
            inline_policies = props.get("Policies", [])
            for policy in inline_policies:
                policy_name = policy.get("PolicyName", "unnamed")
                policy_doc = policy.get("PolicyDocument", {})
                statements = _extract_statements(policy_doc)

                for stmt in statements:
                    if stmt.get("Effect", "Allow") != "Allow":
                        continue
                    actions = _normalise_actions(stmt.get("Action", []))
                    resources_list = _normalise_resources(stmt.get("Resource", []))
                    sid = stmt.get("Sid", "")
                    conditions = stmt.get("Condition", {})

                    risk = _risk_level(actions, resources_list)
                    has_wildcard = any(_is_wildcard(r) for r in resources_list)
                    can_scope = has_wildcard and not all(
                        a.startswith("Describe") or a.startswith("List") or a.startswith("Get")
                        for a in actions
                    )

                    perm_entry: dict[str, Any] = {
                        "role": resource_name,
                        "policy": policy_name,
                        "sid": sid,
                        "actions": actions,
                        "resources": resources_list,
                        "has_conditions": bool(conditions),
                        "has_wildcard_resource": has_wildcard,
                        "can_be_scoped": can_scope,
                        "risk_level": risk,
                    }
                    all_permissions.append(perm_entry)
                    role_info["permission_count"] += len(actions)

                    if risk in ("CRITICAL", "HIGH"):
                        for action in actions:
                            if action.lower() in {h.lower() for h in HIGH_RISK_ACTIONS}:
                                findings.append({
                                    "severity": risk,
                                    "role": resource_name,
                                    "policy": policy_name,
                                    "action": action,
                                    "resource": resources_list,
                                    "description": (
                                        f"{action} granted on "
                                        f"{', '.join(resources_list)}"
                                    ),
                                })
                    elif has_wildcard:
                        findings.append({
                            "severity": "LOW",
                            "role": resource_name,
                            "policy": policy_name,
                            "action": actions,
                            "resource": resources_list,
                            "description": (
                                f"Wildcard resource on "
                                f"{', '.join(actions[:3])}"
                                + (" ..." if len(actions) > 3 else "")
                            ),
                        })

                role_info["policies"].append(policy_name)

            roles.append(role_info)

        total_perms = sum(len(p["actions"]) for p in all_permissions)
        wildcard_perms = sum(
            len(p["actions"]) for p in all_permissions if p["has_wildcard_resource"]
        )
        scopeable = sum(
            len(p["actions"]) for p in all_permissions if p["can_be_scoped"]
        )
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        high = [f for f in findings if f["severity"] == "HIGH"]
        medium = [f for f in findings if f["severity"] == "MEDIUM"]

        return {
            "file": cft_path,
            "roles": roles,
            "summary": {
                "total_roles": len(roles),
                "total_permissions": total_perms,
                "wildcard_resource_permissions": wildcard_perms,
                "scopeable_permissions": scopeable,
                "non_scopeable_wildcards": wildcard_perms - scopeable,
                "critical_findings": len(critical),
                "high_findings": len(high),
                "medium_findings": len(medium),
                "total_findings": len(findings),
            },
            "findings": findings,
            "permissions": all_permissions,
        }
