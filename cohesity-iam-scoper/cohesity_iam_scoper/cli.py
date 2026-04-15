"""Main CLI interface for Cohesity IAM Scoper."""

import json
import os
import re
import sys

import click
from rich.console import Console

from cohesity_iam_scoper.parsers.cft_parser import CFTParser
from cohesity_iam_scoper.parsers.openapi_parser import OpenAPIParser
from cohesity_iam_scoper.mappers.permission_map import PermissionMapper
from cohesity_iam_scoper.mappers.feature_detector import FeatureDetector
from cohesity_iam_scoper.generators.policy_generator import PolicyGenerator
from cohesity_iam_scoper.generators.cft_generator import CFTGenerator
from cohesity_iam_scoper.generators.comparison import PolicyComparator
from cohesity_iam_scoper.validators.dry_run import DryRunValidator
from cohesity_iam_scoper.ui.questionnaire import Questionnaire
from cohesity_iam_scoper.ui.output import OutputFormatter

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="cohesity-iam-scoper")
def cli():
    """Cohesity IAM Scoper - Generate least-privilege AWS IAM policies for Cohesity Cloud Edition.

    \b
    This tool analyzes your Cohesity deployment workflows and generates scoped IAM
    policies based on actual usage, eliminating overly broad wildcard permissions.

    \b
    Quick start:
      cohesity-iam-scoper configure   # Interactive setup wizard
      cohesity-iam-scoper generate    # Generate scoped policy
    """


@cli.command()
@click.option("--config", default="cohesity-config.json", show_default=True,
              help="Path to write the configuration file.")
def init(config):
    """Initialize a new Cohesity IAM Scoper configuration.

    Creates a starter configuration file that you can edit manually or
    populate using the 'configure' command.
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    if os.path.exists(config):
        console.print(f"[yellow]Configuration file '{config}' already exists.[/yellow]")
        if not click.confirm("Overwrite?"):
            console.print("[yellow]Init cancelled.[/yellow]")
            return

    starter_config = {
        "version": "1.0",
        "aws": {
            "account_id": "",
            "cohesity_account_id": "",
            "tag_key": "CohesityManaged",
            "tag_value": "true"
        },
        "selected_features": [],
        "s3": {
            "bucket_pattern": "cohesity-*",
            "existing_buckets": [],
            "allow_bucket_creation": True,
            "kms_encryption": False,
            "kms_key_arn": ""
        },
        "ec2": {
            "vpc_ids": [],
            "subnet_ids": [],
            "instance_types": [],
            "use_tagging_conditions": True
        },
        "rds": {
            "snapshot_prefix": "cohesity-",
            "allowed_engines": []
        },
        "iam": {
            "role_name_prefix": "Cohesity",
            "use_permissions_boundary": False,
            "permissions_boundary_arn": ""
        },
        "output": {
            "format": "cloudformation",
            "output_file": "scoped-cft.json"
        }
    }

    with open(config, "w") as f:
        json.dump(starter_config, f, indent=2)

    formatter.print_success(f"Configuration file created: [bold]{config}[/bold]")
    console.print(
        "\n[dim]Next steps:[/dim]\n"
        f"  1. Edit [bold]{config}[/bold] with your AWS details, or\n"
        "  2. Run [bold]cohesity-iam-scoper configure[/bold] for an interactive setup\n"
        "  3. Run [bold]cohesity-iam-scoper generate[/bold] to generate a scoped policy"
    )


@cli.command()
@click.option("--cft", required=True, type=click.Path(exists=True),
              help="Path to existing CloudFormation template to analyze.")
@click.option("--output", default=None,
              help="Save analysis report to this file path.")
def analyze(cft, output):
    """Analyze an existing CloudFormation template for over-privileged permissions.

    Identifies wildcard resources, high-risk actions, and scoping opportunities
    in your current CFT.

    \b
    Example:
      cohesity-iam-scoper analyze --cft cft.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    console.print(f"[cyan]Analyzing:[/cyan] {cft}\n")

    parser = CFTParser()
    try:
        analysis = parser.analyze(cft)
    except Exception as exc:
        formatter.print_error(f"Failed to parse CFT: {exc}")
        sys.exit(1)

    formatter.print_cft_analysis(analysis)

    if output:
        with open(output, "w") as f:
            json.dump(analysis, f, indent=2)
        formatter.print_success(f"Analysis report saved to: [bold]{output}[/bold]")


@cli.command()
@click.option("--config", default="cohesity-config.json", show_default=True,
              help="Path to write the configuration file.")
def configure(config):
    """Run the interactive configuration wizard.

    Guides you through selecting Cohesity workflows and collecting the AWS
    environment details needed to generate a scoped IAM policy.

    \b
    Example:
      cohesity-iam-scoper configure
      cohesity-iam-scoper configure --config my-env.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    questionnaire = Questionnaire()
    configuration = questionnaire.run()

    with open(config, "w") as f:
        json.dump(configuration, f, indent=2)

    formatter.print_success(
        f"Configuration saved to: [bold]{config}[/bold]\n"
        "Run [bold]cohesity-iam-scoper generate[/bold] to create your scoped policy."
    )


@cli.command()
@click.option("--config", default="cohesity-config.json", show_default=True,
              type=click.Path(exists=True),
              help="Path to configuration file (from 'configure' or 'init').")
@click.option("--output", default=None,
              help="Output file path. Overrides config output.output_file (default: scoped-cft.json).")
@click.option("--format", "output_format",
              type=click.Choice(["cloudformation", "iam-policy"], case_sensitive=False),
              default="cloudformation", show_default=True,
              help="Output format: CloudFormation template or raw IAM policy JSON.")
@click.option("--account-id", default=None,
              help="AWS account ID (exactly 12 digits). Overrides aws.account_id in config.")
@click.option("--features", default=None,
              help="Comma-separated feature keys to enable. Overrides selected_features in config.")
@click.option("--permission-map", "permission_map", default=None,
              type=click.Path(exists=True),
              help="Path to a custom aws_permission_map.json (extends built-in map).")
@click.option("--cohesity-account-id", "cohesity_account_id", default=None,
              help="Account ID where Cohesity CE runs (trust policies). Overrides aws.cohesity_account_id in config.")
def generate(config, output, output_format, account_id, features, permission_map, cohesity_account_id):
    """Generate a scoped IAM policy based on your configuration.

    Reads your configuration and produces a minimal IAM policy or CloudFormation
    template with only the permissions required for your selected workflows.
    CLI flags override values in the config file when both are supplied.

    \b
    Example:
      cohesity-iam-scoper generate
      cohesity-iam-scoper generate --config my-env.json --output scoped-cft.json
      cohesity-iam-scoper generate --account-id 123456789012
      cohesity-iam-scoper generate --features ec2_vm_backup,rds_backup
      cohesity-iam-scoper generate --format iam-policy --output policy.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    with open(config) as f:
        configuration = json.load(f)

    # --- Apply CLI overrides onto the loaded config ---
    if account_id is not None:
        if not re.match(r'^\d{12}$', account_id):
            formatter.print_error(
                f"--account-id '{account_id}' is invalid: must be exactly 12 digits."
            )
            sys.exit(1)
        configuration.setdefault("aws", {})["account_id"] = account_id

    if cohesity_account_id is not None:
        if not re.match(r'^\d{12}$', cohesity_account_id):
            formatter.print_error(
                f"--cohesity-account-id '{cohesity_account_id}' is invalid: must be exactly 12 digits."
            )
            sys.exit(1)
        configuration.setdefault("aws", {})["cohesity_account_id"] = cohesity_account_id

    if features is not None:
        feature_list = [f.strip() for f in features.split(",") if f.strip()]
        configuration["selected_features"] = feature_list

    # Resolve output path: CLI flag > config file value > hardcoded default
    resolved_output = (
        output
        or configuration.get("output", {}).get("output_file")
        or "scoped-cft.json"
    )

    # Validate tag value against the IAM tag value allowed character set.
    _tag_value = configuration.get("aws", {}).get("tag_value", "")
    if _tag_value and not re.match(r'^[\w _.:/=+\-@]*$', _tag_value):
        formatter.print_error(
            f"aws.tag_value '{_tag_value}' contains characters not allowed in IAM tag values.\n"
            "Allowed: letters, numbers, spaces, and _ . : / = + - @"
        )
        sys.exit(1)

    console.print(f"[cyan]Loaded configuration:[/cyan] {config}")

    mapper = PermissionMapper(data_file=permission_map) if permission_map else PermissionMapper()
    detector = FeatureDetector(mapper)

    if not configuration.get("selected_features"):
        console.print(
            "\n[bold yellow]⚠  WARNING:[/bold yellow] [yellow]selected_features is empty — "
            "generating permissions for ALL features.[/yellow]\n"
            "[dim]Run [bold]cohesity-iam-scoper configure[/bold] to select only the features "
            "you need and reduce the permission surface by up to 45%.[/dim]\n"
        )

    permissions = detector.resolve_permissions(configuration)

    if output_format.lower() == "cloudformation":
        generator = CFTGenerator()
        result = generator.generate(permissions, configuration)
    else:
        generator = PolicyGenerator()
        result = generator.generate(permissions, configuration)

    with open(resolved_output, "w") as f:
        json.dump(result, f, indent=2)

    formatter.print_generated_summary(permissions, resolved_output, output_format)


@cli.command()
@click.option("--current", required=True, type=click.Path(exists=True),
              help="Path to the current (existing) CFT or IAM policy file.")
@click.option("--scoped", required=True, type=click.Path(exists=True),
              help="Path to the scoped (generated) CFT or IAM policy file.")
@click.option("--format", "output_format",
              type=click.Choice(["table", "json"], case_sensitive=False),
              default="table", show_default=True,
              help="Report output format.")
@click.option("--output", default=None,
              help="Save comparison report to this file path.")
def compare(current, scoped, output_format, output):
    """Compare current vs. scoped IAM policies side by side.

    Shows risk reduction, permission counts, and which high-risk wildcards
    have been eliminated.

    \b
    Example:
      cohesity-iam-scoper compare --current cft.json --scoped scoped-cft.json
      cohesity-iam-scoper compare --current cft.json --scoped scoped-cft.json --format json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    comparator = PolicyComparator()

    try:
        report = comparator.compare(current, scoped)
    except Exception as exc:
        formatter.print_error(f"Comparison failed: {exc}")
        sys.exit(1)

    if output_format == "json":
        if output:
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
            formatter.print_success(f"Comparison report saved to: [bold]{output}[/bold]")
        else:
            console.print_json(json.dumps(report, indent=2))
    else:
        formatter.print_comparison_report(report)
        if output:
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
            formatter.print_success(f"Report also saved to: [bold]{output}[/bold]")


@cli.command()
@click.option("--policy", required=True, type=click.Path(exists=True),
              help="Path to the IAM policy or CFT to validate.")
@click.option("--profile", default=None,
              help="AWS CLI profile to use for validation.")
@click.option("--region", default="us-east-1", show_default=True,
              help="AWS region for validation.")
def validate(policy, profile, region):
    """Dry-run validate permissions against AWS IAM Policy Simulator.

    Checks that the generated policy grants the required permissions without
    invoking actual AWS API calls.

    \b
    Note: Requires valid AWS credentials configured.

    \b
    Example:
      cohesity-iam-scoper validate --policy scoped-cft.json
      cohesity-iam-scoper validate --policy scoped-cft.json --profile my-profile
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    validator = DryRunValidator(profile=profile, region=region)

    console.print(f"[cyan]Validating:[/cyan] {policy}\n")

    try:
        results = validator.validate(policy)
        formatter.print_validation_results(results)
    except Exception as exc:
        formatter.print_error(f"Validation failed: {exc}")
        sys.exit(1)


@cli.command("parse-openapi")
@click.option("--spec", required=True, type=click.Path(exists=True),
              help="Path to OpenAPI YAML spec file (v1 or v2).")
@click.option("--output", default=None,
              help="Save parsed AWS-relevant endpoints to this JSON file.")
@click.option("--filter-aws/--no-filter-aws", default=True, show_default=True,
              help="Filter to only AWS-relevant endpoints.")
def parse_openapi(spec, output, filter_aws):
    """Parse a Cohesity OpenAPI spec and extract AWS-relevant endpoints.

    Analyzes the v1 or v2 OpenAPI spec to identify all endpoints related to
    AWS operations (EC2, RDS, S3, DynamoDB, Glacier).

    \b
    Example:
      cohesity-iam-scoper parse-openapi --spec cluster_v2_api.yaml
      cohesity-iam-scoper parse-openapi --spec cluster_v1_api.yaml --output v1-aws-ops.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    console.print(f"[cyan]Parsing OpenAPI spec:[/cyan] {spec}\n")

    parser = OpenAPIParser()
    try:
        endpoints = parser.parse(spec, aws_only=filter_aws)
    except Exception as exc:
        formatter.print_error(f"Failed to parse OpenAPI spec: {exc}")
        sys.exit(1)

    formatter.print_openapi_summary(endpoints)

    if output:
        with open(output, "w") as f:
            json.dump(endpoints, f, indent=2)
        formatter.print_success(f"Parsed endpoints saved to: [bold]{output}[/bold]")


if __name__ == "__main__":
    cli()
