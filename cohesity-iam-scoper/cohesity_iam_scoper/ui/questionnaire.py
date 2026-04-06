"""Interactive questionnaire for Cohesity IAM Scoper configuration."""

from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich import box

from cohesity_iam_scoper.mappers.feature_detector import FeatureDetector, FEATURE_DISPLAY_NAMES
from cohesity_iam_scoper.mappers.permission_map import PermissionMapper

console = Console()

RISK_COLOR = {
    "CRITICAL": "red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}

ALL_FEATURES_ORDERED = [
    ("source_registration_aws", "AWS Source Registration (required for all workflows)"),
    ("ec2_vm_backup", "EC2 VM Backup (snapshots, EBS volumes)"),
    ("ebs_direct_api", "EBS Direct API (block-level incremental backups)"),
    ("ec2_vm_restore", "EC2 VM Restore / CloudSpin"),
    ("rds_backup", "RDS Backup (DB snapshots, Aurora clusters)"),
    ("rds_restore", "RDS Restore (point-in-time, snapshot restore)"),
    ("rds_db_connect", "RDS DB Connect (IAM auth for app-aware backups)"),
    ("rds_staging_s3", "RDS Backup S3 Staging (cross-region/account restores)"),
    ("redshift_backup", "Redshift Backup (cluster data protection)"),
    ("dynamodb_backup", "DynamoDB Backup (on-demand backups, PITR exports)"),
    ("s3_protection", "S3 Protection (S3 buckets as data source)"),
    ("s3_archive", "S3 Archive (long-term backup archival to S3)"),
    ("glacier_archive", "Glacier Archive (S3 Glacier / Deep Archive)"),
    ("iam_role_management", "IAM Role Management (create/manage Cohesity roles)"),
    ("instance_role", "Cohesity Instance Role (cross-account assumption)"),
    ("ssm_operations", "SSM Operations (app-consistent EC2 snapshots)"),
    ("cloudformation_management", "CloudFormation Stack Management"),
    ("kms_encryption", "KMS Encryption (customer-managed keys)"),
]


class Questionnaire:
    """Guides the user through interactive configuration collection."""

    def __init__(self) -> None:
        self._mapper = PermissionMapper()
        self._detector = FeatureDetector(self._mapper)

    def run(self) -> dict[str, Any]:
        """Run the full interactive questionnaire.

        Returns:
            A configuration dict ready to save as JSON.
        """
        console.print(
            Panel(
                "[bold cyan]Cohesity IAM Scoper - Configuration Wizard[/bold cyan]\n"
                "[dim]Answer the following questions to generate a scoped IAM policy.[/dim]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        selected_features = self._ask_features()
        aws_config = self._ask_aws_config(selected_features)
        s3_config = self._ask_s3_config(selected_features)
        ec2_config = self._ask_ec2_config(selected_features)
        rds_config = self._ask_rds_config(selected_features)
        iam_config = self._ask_iam_config(selected_features)
        output_config = self._ask_output_config()

        config = {
            "version": "1.0",
            "aws": aws_config,
            "selected_features": selected_features,
            "s3": s3_config,
            "ec2": ec2_config,
            "rds": rds_config,
            "iam": iam_config,
            "output": output_config,
        }

        self._print_summary(config)
        return config

    def _ask_features(self) -> list[str]:
        """Ask which Cohesity workflows the customer needs."""
        console.print("\n[bold]Step 1: Select Cohesity Workflows[/bold]")
        console.print(
            "[dim]Choose the Cohesity operations you need in AWS. "
            "This determines the minimum required IAM permissions.[/dim]\n"
        )

        mapper = self._mapper
        table = Table(
            box=box.ROUNDED, show_header=True, header_style="bold magenta",
            title="Available Cohesity Workflows"
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Workflow", style="bold")
        table.add_column("Risk Level", justify="center")
        table.add_column("Description", style="dim")

        for idx, (key, display) in enumerate(ALL_FEATURES_ORDERED, start=1):
            risk = mapper.get_risk_level(key)
            color = RISK_COLOR.get(risk, "white")
            feature = mapper.get_feature(key)
            desc = feature.get("description", "")[:60] + (
                "..." if len(feature.get("description", "")) > 60 else ""
            )
            table.add_row(
                str(idx),
                display,
                f"[{color}]{risk}[/{color}]",
                desc,
            )

        console.print(table)
        console.print()

        raw = Prompt.ask(
            "Enter workflow numbers (comma-separated, e.g. [cyan]1,2,4[/cyan], or "
            "[cyan]all[/cyan] for everything)",
            default="1,2,4",
        )

        selected: list[str] = []
        if raw.strip().lower() == "all":
            selected = [key for key, _ in ALL_FEATURES_ORDERED]
        else:
            for part in raw.split(","):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(ALL_FEATURES_ORDERED):
                        key = ALL_FEATURES_ORDERED[idx][0]
                        if key not in selected:
                            selected.append(key)

        if not selected:
            console.print(
                "[yellow]No workflows selected. Defaulting to source registration.[/yellow]"
            )
            selected = ["source_registration_aws"]

        if "source_registration_aws" not in selected and len(selected) > 0:
            console.print(
                "[yellow]ℹ️  Adding 'AWS Source Registration' (required for all workflows)[/yellow]"
            )
            selected.insert(0, "source_registration_aws")

        console.print(
            f"\n[green]✓ Selected {len(selected)} workflow(s):[/green] "
            + ", ".join(
                FEATURE_DISPLAY_NAMES.get(k, k) for k in selected
            )
        )
        return selected

    def _ask_aws_config(self, features: list[str]) -> dict[str, Any]:
        """Ask for AWS account and region information."""
        console.print("\n[bold]Step 2: AWS Account Configuration[/bold]\n")

        account_id = Prompt.ask(
            "AWS Account ID [dim](leave blank to use ${AWS::AccountId} placeholder)[/dim]",
            default="",
        ).strip()

        regions_raw = Prompt.ask(
            "AWS regions where Cohesity operates [dim](comma-separated)[/dim]",
            default="us-east-1",
        )
        regions = [r.strip() for r in regions_raw.split(",") if r.strip()]

        tag_key = Prompt.ask(
            "Tag key for Cohesity-managed resources",
            default="CohesityManaged",
        )
        tag_value = Prompt.ask(
            "Tag value for Cohesity-managed resources",
            default="true",
        )

        return {
            "account_id": account_id,
            "regions": regions,
            "tag_key": tag_key,
            "tag_value": tag_value,
        }

    def _ask_s3_config(self, features: list[str]) -> dict[str, Any]:
        """Ask for S3-specific configuration if S3 features are selected."""
        s3_features = {"s3_archive", "glacier_archive", "rds_staging_s3"}
        if not s3_features.intersection(features):
            return {
                "bucket_pattern": "cohesity-*",
                "existing_buckets": [],
                "allow_bucket_creation": False,
                "kms_encryption": False,
                "kms_key_arn": "",
            }

        console.print("\n[bold]Step 3: S3 Configuration[/bold]\n")

        buckets_raw = Prompt.ask(
            "Existing S3 bucket names for Cohesity archives "
            "[dim](comma-separated, leave blank if none yet)[/dim]",
            default="",
        )
        existing_buckets = [
            b.strip() for b in buckets_raw.split(",") if b.strip()
        ]

        bucket_pattern = Prompt.ask(
            "S3 bucket naming pattern to scope permissions "
            "[dim](e.g. cohesity-*, my-company-cohesity-*)[/dim]",
            default="cohesity-*",
        )

        allow_create = Confirm.ask(
            "Allow Cohesity to create new S3 buckets?", default=True
        )

        kms = Confirm.ask(
            "Require KMS encryption for S3 objects?", default=False
        )
        kms_key_arn = ""
        if kms:
            kms_key_arn = Prompt.ask(
                "KMS key ARN [dim](leave blank for any key)[/dim]", default=""
            ).strip()

        return {
            "bucket_pattern": bucket_pattern,
            "existing_buckets": existing_buckets,
            "allow_bucket_creation": allow_create,
            "kms_encryption": kms,
            "kms_key_arn": kms_key_arn,
        }

    def _ask_ec2_config(self, features: list[str]) -> dict[str, Any]:
        """Ask for EC2-specific configuration if EC2 features are selected."""
        ec2_features = {"ec2_vm_backup", "ec2_vm_restore", "ssm_operations"}
        if not ec2_features.intersection(features):
            return {
                "vpc_ids": [],
                "subnet_ids": [],
                "instance_types": [],
                "use_tagging_conditions": True,
            }

        console.print("\n[bold]Step 4: EC2 Configuration[/bold]\n")

        vpcs_raw = Prompt.ask(
            "Restrict EC2 operations to specific VPC IDs? "
            "[dim](comma-separated, leave blank for all VPCs)[/dim]",
            default="",
        )
        vpc_ids = [v.strip() for v in vpcs_raw.split(",") if v.strip()]

        subnets_raw = Prompt.ask(
            "Restrict EC2 launches to specific subnet IDs? "
            "[dim](comma-separated, leave blank for all subnets)[/dim]",
            default="",
        )
        subnet_ids = [s.strip() for s in subnets_raw.split(",") if s.strip()]

        use_tagging = Confirm.ask(
            "Add tag conditions to restrict EC2 operations to Cohesity-tagged resources?",
            default=True,
        )

        return {
            "vpc_ids": vpc_ids,
            "subnet_ids": subnet_ids,
            "instance_types": [],
            "use_tagging_conditions": use_tagging,
        }

    def _ask_rds_config(self, features: list[str]) -> dict[str, Any]:
        """Ask for RDS-specific configuration if RDS features are selected."""
        rds_features = {"rds_backup", "rds_restore", "rds_staging_s3"}
        if not rds_features.intersection(features):
            return {"snapshot_prefix": "cohesity-", "allowed_engines": []}

        console.print("\n[bold]Step 5: RDS Configuration[/bold]\n")

        prefix = Prompt.ask(
            "Prefix for Cohesity-managed RDS snapshots",
            default="cohesity-",
        )

        return {
            "snapshot_prefix": prefix,
            "allowed_engines": [],
        }

    def _ask_iam_config(self, features: list[str]) -> dict[str, Any]:
        """Ask for IAM-specific configuration."""
        console.print("\n[bold]Step 6: IAM Role Configuration[/bold]\n")

        role_prefix = Prompt.ask(
            "Prefix for Cohesity IAM roles "
            "[dim](roles will match arn:aws:iam::*:role/{prefix}*)[/dim]",
            default="Cohesity",
        )

        use_boundary = Confirm.ask(
            "Use a permissions boundary to constrain Cohesity roles?", default=False
        )
        boundary_arn = ""
        if use_boundary:
            boundary_arn = Prompt.ask(
                "Permissions boundary ARN "
                "[dim](e.g. arn:aws:iam::123456789012:policy/CohesityBoundary)[/dim]",
                default="",
            ).strip()

        return {
            "role_name_prefix": role_prefix,
            "use_permissions_boundary": use_boundary,
            "permissions_boundary_arn": boundary_arn,
        }

    def _ask_output_config(self) -> dict[str, Any]:
        """Ask for output format preferences."""
        console.print("\n[bold]Step 7: Output Configuration[/bold]\n")

        fmt = Prompt.ask(
            "Output format",
            choices=["cloudformation", "iam-policy"],
            default="cloudformation",
        )
        output_file = Prompt.ask(
            "Output file name",
            default="scoped-cft.json" if fmt == "cloudformation" else "scoped-policy.json",
        )

        return {"format": fmt, "output_file": output_file}

    def _print_summary(self, config: dict[str, Any]) -> None:
        """Print a configuration summary before saving."""
        console.print("\n")
        console.print(
            Panel(
                "[bold green]Configuration Summary[/bold green]",
                border_style="green",
            )
        )

        aws = config.get("aws", {})
        console.print(f"  [cyan]Account ID:[/cyan]  {aws.get('account_id') or '(placeholder)'}")
        console.print(f"  [cyan]Regions:[/cyan]     {', '.join(aws.get('regions', []))}")
        console.print(f"  [cyan]Tag Key:[/cyan]     {aws.get('tag_key', 'CohesityManaged')}")

        features = config.get("selected_features", [])
        console.print(
            f"\n  [cyan]Workflows ({len(features)}):[/cyan] "
            + ", ".join(FEATURE_DISPLAY_NAMES.get(f, f) for f in features)
        )

        out = config.get("output", {})
        console.print(f"\n  [cyan]Output:[/cyan]  {out.get('output_file')} ({out.get('format')})")
        console.print()
