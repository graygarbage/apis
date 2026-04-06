"""Dry-run validator using AWS IAM Policy Simulator."""

import json
from typing import Any, Optional


class DryRunValidator:
    """Validates generated policies via AWS IAM Policy Simulator (read-only).

    This validator uses boto3 to call the IAM Policy Simulator API which
    simulates API calls without making actual AWS API calls.
    """

    def __init__(self, profile: Optional[str] = None, region: str = "us-east-1") -> None:
        self._profile = profile
        self._region = region
        self._session = None

    def _get_session(self):
        """Lazily create a boto3 session."""
        if self._session is None:
            try:
                import boto3
                if self._profile:
                    self._session = boto3.Session(
                        profile_name=self._profile, region_name=self._region
                    )
                else:
                    self._session = boto3.Session(region_name=self._region)
            except ImportError:
                raise RuntimeError(
                    "boto3 is required for validation. "
                    "Install it with: pip install boto3"
                )
        return self._session

    def validate(self, policy_path: str) -> dict[str, Any]:
        """Validate a policy file against the IAM Policy Simulator.

        Args:
            policy_path: Path to an IAM policy JSON file or CloudFormation template.

        Returns:
            Validation results dict with pass/fail per action.
        """
        policy_doc = self._load_policy(policy_path)
        all_actions = self._extract_actions(policy_doc)

        try:
            session = self._get_session()
            iam = session.client("iam")
            results = self._simulate(iam, policy_doc, all_actions)
            return {
                "status": "completed",
                "policy_file": policy_path,
                "total_actions": len(all_actions),
                "results": results,
                "allowed_count": sum(
                    1 for r in results if r.get("decision") == "allowed"
                ),
                "denied_count": sum(
                    1 for r in results if r.get("decision") != "allowed"
                ),
            }
        except Exception as exc:
            return {
                "status": "error",
                "policy_file": policy_path,
                "error": str(exc),
                "note": (
                    "Ensure valid AWS credentials are configured. "
                    "Run 'aws configure' or set AWS_PROFILE environment variable."
                ),
                "total_actions": len(all_actions),
                "actions_found": all_actions,
            }

    def _load_policy(self, policy_path: str) -> dict[str, Any]:
        """Load and normalise a policy or CFT file to an IAM policy document."""
        with open(policy_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        if "AWSTemplateFormatVersion" in data or "Resources" in data:
            policy_stmts: list[dict] = []
            for resource in data.get("Resources", {}).values():
                if resource.get("Type") != "AWS::IAM::Role":
                    continue
                for policy in resource.get("Properties", {}).get("Policies", []):
                    stmts = (
                        policy.get("PolicyDocument", {}).get("Statement", [])
                    )
                    policy_stmts.extend(stmts)
            return {"Version": "2012-10-17", "Statement": policy_stmts}

        return data

    def _extract_actions(self, policy_doc: dict[str, Any]) -> list[str]:
        """Extract all unique IAM actions from a policy document."""
        actions: set[str] = set()
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            raw = stmt.get("Action", [])
            if isinstance(raw, str):
                actions.add(raw)
            elif isinstance(raw, list):
                actions.update(raw)
        return sorted(actions)

    def _simulate(
        self,
        iam_client: Any,
        policy_doc: dict[str, Any],
        actions: list[str],
    ) -> list[dict[str, Any]]:
        """Run IAM policy simulation in batches of 100 actions."""
        results: list[dict[str, Any]] = []
        policy_json = json.dumps(policy_doc)

        batch_size = 100
        for i in range(0, len(actions), batch_size):
            batch = actions[i : i + batch_size]
            response = iam_client.simulate_custom_policy(
                PolicyInputList=[policy_json],
                ActionNames=batch,
                ResourceArns=["*"],
            )
            for result in response.get("EvaluationResults", []):
                results.append({
                    "action": result.get("EvalActionName"),
                    "decision": result.get("EvalDecision"),
                    "resource": result.get("EvalResourceName"),
                })

        return results
