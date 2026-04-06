"""Pretty terminal output using the Rich library."""

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
    "UNKNOWN": "white",
}

RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "⚠️ ",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️ ",
}

BANNER = """[bold cyan]
  ╔═══════════════════════════════════════════╗
  ║   Cohesity IAM Scoper  v1.0.0            ║
  ║   Least-Privilege AWS IAM Policy Tool    ║
  ╚═══════════════════════════════════════════╝
[/bold cyan]"""


class OutputFormatter:
    """Provides rich-formatted terminal output for all CLI commands."""

    def print_banner(self) -> None:
        """Print the CLI tool banner."""
        console.print(BANNER)

    def print_success(self, message: str) -> None:
        """Print a green success message."""
        console.print(f"\n[bold green]✅  {message}[/bold green]\n")

    def print_error(self, message: str) -> None:
        """Print a red error message."""
        console.print(f"\n[bold red]❌  Error: {message}[/bold red]\n")

    def print_warning(self, message: str) -> None:
        """Print a yellow warning message."""
        console.print(f"\n[yellow]⚠️   {message}[/yellow]\n")

    def print_cft_analysis(self, analysis: dict[str, Any]) -> None:
        """Pretty-print the CFT analysis report."""
        summary = analysis["summary"]
        findings = analysis["findings"]

        console.print(
            Panel(
                f"[bold]File:[/bold] {analysis['file']}",
                title="[bold cyan]CFT Risk Assessment[/bold cyan]",
                border_style="cyan",
            )
        )

        metrics_table = Table(
            box=box.ROUNDED, show_header=False, padding=(0, 2)
        )
        metrics_table.add_column("Metric", style="bold")
        metrics_table.add_column("Value", justify="right")

        metrics_table.add_row("IAM Roles found", str(summary["total_roles"]))
        metrics_table.add_row("Total permissions", str(summary["total_permissions"]))
        metrics_table.add_row(
            "Permissions with wildcard resource",
            f"[red]{summary['wildcard_resource_permissions']}[/red]",
        )
        metrics_table.add_row(
            "Permissions that can be scoped",
            f"[green]{summary['scopeable_permissions']}[/green]",
        )

        console.print(metrics_table)
        console.print()

        if findings:
            console.print("[bold]Findings by severity:[/bold]")

            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                sev_findings = [f for f in findings if f.get("severity") == severity]
                if not sev_findings:
                    continue
                color = RISK_COLOR.get(severity, "white")
                emoji = RISK_EMOJI.get(severity, "•")
                console.print(
                    f"  [{color}]{emoji} {severity} ({len(sev_findings)} findings):[/{color}]"
                )
                for finding in sev_findings[:5]:
                    desc = finding.get("description", "")
                    console.print(f"    [dim]•[/dim] {desc}")
                if len(sev_findings) > 5:
                    console.print(
                        f"    [dim]... and {len(sev_findings) - 5} more[/dim]"
                    )
            console.print()

        console.print("[bold]Scoping opportunities:[/bold]")
        console.print(
            f"  [yellow]→[/yellow] {summary['wildcard_resource_permissions']} permissions "
            f"use [bold]Resource: *[/bold]"
        )
        console.print(
            f"  [green]→[/green] {summary['scopeable_permissions']} can be scoped to "
            "specific resources"
        )
        non_scopeable = summary.get("non_scopeable_wildcards", 0)
        if non_scopeable > 0:
            console.print(
                f"  [cyan]→[/cyan] {non_scopeable} require [bold]Resource: *[/bold] "
                "(read-only Describe/List/Get)"
            )
        console.print()

    def print_comparison_report(self, report: dict[str, Any]) -> None:
        """Pretty-print the side-by-side comparison report."""
        current = report["current"]
        scoped = report["scoped"]
        delta = report["delta"]

        console.print(
            Panel(
                f"[bold]Current:[/bold] {report['current_file']}\n"
                f"[bold]Scoped: [/bold] {report['scoped_file']}",
                title="[bold cyan]Policy Comparison Report[/bold cyan]",
                border_style="cyan",
            )
        )

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            title="Permission Comparison",
        )
        table.add_column("Metric", style="bold")
        table.add_column("Current CFT", justify="right", style="red")
        table.add_column("Scoped CFT", justify="right", style="green")
        table.add_column("Change", justify="right")

        def _delta_str(curr: int, scop: int) -> str:
            diff = scop - curr
            if diff < 0:
                return f"[green]↓ {abs(diff)}[/green]"
            if diff > 0:
                return f"[red]↑ {diff}[/red]"
            return "[dim]—[/dim]"

        table.add_row(
            "IAM Roles",
            str(current["total_roles"]),
            str(scoped["total_roles"]),
            _delta_str(current["total_roles"], scoped["total_roles"]),
        )
        table.add_row(
            "Total Permissions",
            str(current["total_permissions"]),
            str(scoped["total_permissions"]),
            _delta_str(current["total_permissions"], scoped["total_permissions"]),
        )
        table.add_row(
            "Wildcard Resource Permissions",
            str(current["wildcard_resource_permissions"]),
            str(scoped["wildcard_resource_permissions"]),
            _delta_str(
                current["wildcard_resource_permissions"],
                scoped["wildcard_resource_permissions"],
            ),
        )
        table.add_row(
            "CRITICAL Findings",
            str(current["critical_findings"]),
            str(scoped["critical_findings"]),
            _delta_str(current["critical_findings"], scoped["critical_findings"]),
        )
        table.add_row(
            "HIGH Findings",
            str(current["high_findings"]),
            str(scoped["high_findings"]),
            _delta_str(current["high_findings"], scoped["high_findings"]),
        )
        table.add_row(
            "MEDIUM Findings",
            str(current["medium_findings"]),
            str(scoped["medium_findings"]),
            _delta_str(current["medium_findings"], scoped["medium_findings"]),
        )

        console.print(table)
        console.print()

        pct = delta.get("permission_reduction_pct", 0)
        wpct = delta.get("wildcard_reduction_pct", 0)
        console.print("[bold]Risk Reduction Summary:[/bold]")
        console.print(
            f"  [green]✅[/green] Permission count reduced by "
            f"[bold green]{pct:.1f}%[/bold green]"
        )
        console.print(
            f"  [green]✅[/green] Wildcard resources reduced by "
            f"[bold green]{wpct:.1f}%[/bold green]"
        )

        eliminated = delta.get("eliminated_risk_actions", [])
        if eliminated:
            console.print(
                f"  [green]✅[/green] {len(eliminated)} high-risk actions eliminated:"
            )
            for action in eliminated[:8]:
                console.print(f"    [dim]•[/dim] {action}")
            if len(eliminated) > 8:
                console.print(f"    [dim]... and {len(eliminated) - 8} more[/dim]")

        remaining = delta.get("remaining_risk_actions", [])
        if remaining:
            console.print(
                f"\n  [yellow]⚠️ [/yellow] {len(remaining)} high-risk actions remain "
                "(review conditions):"
            )
            for action in remaining[:5]:
                console.print(f"    [dim]•[/dim] {action}")

        console.print()

    def print_generated_summary(
        self,
        permissions: dict[str, Any],
        output_file: str,
        output_format: str,
    ) -> None:
        """Print a summary after generating a scoped policy."""
        total = permissions.get("total_count", 0)
        by_service = permissions.get("permissions_by_service", {})
        features = permissions.get("selected_features", [])

        console.print(
            Panel(
                f"[bold]Output:[/bold] {output_file}  "
                f"([dim]{output_format}[/dim])",
                title="[bold green]Generated Policy Summary[/bold green]",
                border_style="green",
            )
        )

        console.print(
            f"  [green]✅[/green] [bold]{total}[/bold] scoped IAM permissions generated"
        )
        console.print(
            f"  [green]✅[/green] {len(features)} Cohesity workflow(s) covered"
        )

        if by_service:
            console.print("\n  [bold]Permissions by AWS service:[/bold]")
            svc_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            svc_table.add_column("Service", style="cyan")
            svc_table.add_column("Count", justify="right")
            for svc, perms in by_service.items():
                svc_table.add_row(svc, str(len(perms)))
            console.print(svc_table)

        console.print()
        console.print(
            f"  [dim]Run [bold]cohesity-iam-scoper compare "
            f"--current cft.json --scoped {output_file}[/bold] to see risk reduction.[/dim]"
        )
        console.print()

    def print_validation_results(self, results: dict[str, Any]) -> None:
        """Print dry-run validation results."""
        status = results.get("status", "unknown")

        if status == "error":
            self.print_warning(
                f"Validation could not complete: {results.get('error', '')}\n"
                f"  {results.get('note', '')}"
            )
            console.print(
                f"  [dim]Actions found in policy: "
                f"{results.get('total_actions', 0)}[/dim]"
            )
            return

        allowed = results.get("allowed_count", 0)
        denied = results.get("denied_count", 0)
        total = results.get("total_actions", 0)

        console.print(
            Panel(
                f"[bold]File:[/bold] {results.get('policy_file', '')}",
                title="[bold cyan]Dry-Run Validation Results[/bold cyan]",
                border_style="cyan",
            )
        )

        if denied == 0:
            console.print(
                f"  [green]✅[/green] All [bold]{total}[/bold] actions are "
                "allowed by the policy"
            )
        else:
            console.print(
                f"  [yellow]⚠️ [/yellow] {allowed}/{total} actions allowed, "
                f"[red]{denied} denied[/red]"
            )
            denied_results = [
                r for r in results.get("results", [])
                if r.get("decision") != "allowed"
            ]
            for r in denied_results[:10]:
                console.print(
                    f"    [red]✗[/red] {r.get('action')} → {r.get('decision')}"
                )
        console.print()

    def print_openapi_summary(self, endpoints: dict[str, Any]) -> None:
        """Print a summary of parsed OpenAPI endpoints."""
        console.print(
            Panel(
                f"[bold]Spec version:[/bold] {endpoints.get('spec_version', '?')}\n"
                f"[bold]Base path:[/bold]    {endpoints.get('base_path', '?')}",
                title="[bold cyan]OpenAPI Parse Results[/bold cyan]",
                border_style="cyan",
            )
        )

        console.print(
            f"  [cyan]Total paths in spec:[/cyan]  "
            f"{endpoints.get('total_endpoints', 0)}"
        )
        console.print(
            f"  [green]AWS-relevant endpoints:[/green]  "
            f"{endpoints.get('aws_relevant_endpoints', 0)}"
        )

        env_types = endpoints.get("aws_environment_types_found", [])
        if env_types:
            console.print(
                f"\n  [bold]AWS environment types found:[/bold] "
                + ", ".join(env_types[:10])
                + ("..." if len(env_types) > 10 else "")
            )

        categories = endpoints.get("categories", {})
        if categories:
            console.print("\n  [bold]Endpoints by category:[/bold]")
            cat_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            cat_table.add_column("Category", style="cyan")
            cat_table.add_column("Count", justify="right")
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                cat_table.add_row(cat, str(count))
            console.print(cat_table)

        console.print()
