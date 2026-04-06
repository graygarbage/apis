"""Policy comparator - compare current vs. scoped IAM policies."""

import json
from typing import Any

from cohesity_iam_scoper.parsers.cft_parser import CFTParser, HIGH_RISK_ACTIONS


class PolicyComparator:
    """Compares current CFT against a scoped CFT and produces a risk delta report."""

    def compare(self, current_path: str, scoped_path: str) -> dict[str, Any]:
        """Compare two policy files and return a comparison report.

        Args:
            current_path: Path to the current (existing) CFT JSON.
            scoped_path:  Path to the scoped (generated) CFT JSON.

        Returns:
            Comparison report dict.
        """
        parser = CFTParser()
        current_analysis = parser.analyze(current_path)
        scoped_analysis = parser.analyze(scoped_path)

        current_summary = current_analysis["summary"]
        scoped_summary = scoped_analysis["summary"]

        current_perms = _collect_all_actions(current_analysis["permissions"])
        scoped_perms = _collect_all_actions(scoped_analysis["permissions"])

        removed_perms = sorted(current_perms - scoped_perms)
        added_perms = sorted(scoped_perms - current_perms)
        retained_perms = sorted(current_perms & scoped_perms)

        current_high_risk = _collect_high_risk_actions(current_analysis["findings"])
        scoped_high_risk = _collect_high_risk_actions(scoped_analysis["findings"])
        eliminated_risk = sorted(current_high_risk - scoped_high_risk)
        remaining_risk = sorted(scoped_high_risk)

        reduction_pct = 0.0
        if current_summary["total_permissions"] > 0:
            reduction_pct = (
                1.0
                - scoped_summary["total_permissions"]
                / current_summary["total_permissions"]
            ) * 100

        wildcard_reduction_pct = 0.0
        cw = current_summary["wildcard_resource_permissions"]
        if cw > 0:
            wildcard_reduction_pct = (
                1.0 - scoped_summary["wildcard_resource_permissions"] / cw
            ) * 100

        return {
            "current_file": current_path,
            "scoped_file": scoped_path,
            "current": {
                "total_roles": current_summary["total_roles"],
                "total_permissions": current_summary["total_permissions"],
                "wildcard_resource_permissions": current_summary[
                    "wildcard_resource_permissions"
                ],
                "critical_findings": current_summary["critical_findings"],
                "high_findings": current_summary["high_findings"],
                "medium_findings": current_summary["medium_findings"],
                "total_findings": current_summary["total_findings"],
            },
            "scoped": {
                "total_roles": scoped_summary["total_roles"],
                "total_permissions": scoped_summary["total_permissions"],
                "wildcard_resource_permissions": scoped_summary[
                    "wildcard_resource_permissions"
                ],
                "critical_findings": scoped_summary["critical_findings"],
                "high_findings": scoped_summary["high_findings"],
                "medium_findings": scoped_summary["medium_findings"],
                "total_findings": scoped_summary["total_findings"],
            },
            "delta": {
                "permissions_removed": len(removed_perms),
                "permissions_added": len(added_perms),
                "permissions_retained": len(retained_perms),
                "permission_reduction_pct": round(reduction_pct, 1),
                "wildcard_reduction_pct": round(wildcard_reduction_pct, 1),
                "risk_findings_eliminated": len(current_high_risk) - len(scoped_high_risk),
                "removed_permissions": removed_perms,
                "added_permissions": added_perms,
                "eliminated_risk_actions": eliminated_risk,
                "remaining_risk_actions": remaining_risk,
            },
        }


def _collect_all_actions(permissions: list[dict]) -> set[str]:
    """Flatten all actions across all permission entries into a set."""
    result: set[str] = set()
    for perm in permissions:
        for action in perm.get("actions", []):
            result.add(action)
    return result


def _collect_high_risk_actions(findings: list[dict]) -> set[str]:
    """Collect action strings from HIGH/CRITICAL findings."""
    result: set[str] = set()
    for finding in findings:
        if finding.get("severity") in ("CRITICAL", "HIGH"):
            action = finding.get("action")
            if isinstance(action, str):
                result.add(action)
            elif isinstance(action, list):
                result.update(action)
    return result
