# Cohesity IAM Scoper

A CLI tool that helps customers implement least-privilege IAM permissions for Cohesity Cloud Edition deployments in AWS. The tool analyzes Cohesity API capabilities (v1/v2) and generates scoped IAM policies based on actual customer usage patterns.

## Overview

The default Cohesity CloudFormation template (`cft.json`) grants overly broad permissions with wildcard resources across IAM, EC2, S3, CloudFormation, and SSM services. This tool generates minimal, scoped IAM policies tailored to the specific Cohesity workflows you actually use.

### Security Problems Solved

| Issue | Risk | Solution |
|-------|------|----------|
| `iam:*` actions with `Resource: *` | CRITICAL | Scope to `arn:aws:iam::*:role/Cohesity*` with permissions boundaries |
| `s3:DeleteObject` on any bucket | HIGH | Scope to named or pattern-matched buckets |
| `ec2:TerminateInstances` without conditions | HIGH | Add `CohesityManaged` tag conditions |
| `ssm:SendCommand` without restrictions | MEDIUM | Restrict to specific SSM documents |
| CloudFormation wildcard resources | MEDIUM | Scope to `Cohesity*` stacks |

## Installation

```bash
# Clone the repository
git clone https://github.com/graygarbage/apis.git
cd apis/cohesity-iam-scoper

# Install with pip
pip install -e .

# Verify installation
cohesity-iam-scoper --version
```

### Requirements

- Python 3.8+
- AWS credentials configured (for `validate` command only)

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Step 1: Run the interactive configuration wizard
cohesity-iam-scoper configure

# Step 2: Generate a scoped CloudFormation template
cohesity-iam-scoper generate --config cohesity-config.json --output scoped-cft.json

# Step 3: Compare the new policy with the original
cohesity-iam-scoper compare --current cft.json --scoped scoped-cft.json
```

## Command Reference

### `init` - Initialize Configuration

Creates a starter configuration file.

```bash
cohesity-iam-scoper init
cohesity-iam-scoper init --config my-environment.json
```

### `configure` - Interactive Wizard

Guides you through selecting workflows and entering your AWS environment details.

```bash
cohesity-iam-scoper configure
cohesity-iam-scoper configure --config production.json
```

The wizard will ask:
- Which Cohesity workflows you need (EC2 backup, RDS backup, S3 archive, etc.)
- AWS account ID and regions
- S3 bucket names/patterns for archives
- VPC/subnet restrictions for EC2 operations
- IAM role naming conventions and permissions boundaries

### `analyze` - Analyze Existing CFT

Parses your current CloudFormation template and identifies over-privileged permissions.

```bash
cohesity-iam-scoper analyze --cft cft.json
cohesity-iam-scoper analyze --cft cft.json --output analysis-report.json
```

**Sample output:**
```
╭─ CFT Risk Assessment ──────────────────────────────────╮
│ File: cft.json                                         │
╰────────────────────────────────────────────────────────╯

  IAM Roles found                   4
  Total permissions               156
  Permissions with wildcard        89
  Permissions that can be scoped   67

⚠️  HIGH (3 findings):
  • iam:CreateRole granted on *
  • s3:DeleteObject granted on arn:aws:s3:::*/*
  • ec2:TerminateInstances granted on *
```

### `generate` - Generate Scoped Policy

Creates a minimal IAM policy or CloudFormation template for your selected workflows.

```bash
# Generate CloudFormation template (default)
cohesity-iam-scoper generate

# Generate raw IAM policy JSON
cohesity-iam-scoper generate --format iam-policy --output scoped-policy.json

# Use custom config and output paths
cohesity-iam-scoper generate \
  --config production.json \
  --output scoped-cft.json \
  --format cloudformation
```

### `compare` - Compare Policies

Shows a side-by-side comparison of the current and scoped policies.

```bash
cohesity-iam-scoper compare --current cft.json --scoped scoped-cft.json

# Output as JSON
cohesity-iam-scoper compare \
  --current cft.json \
  --scoped scoped-cft.json \
  --format json \
  --output comparison-report.json
```

**Sample output:**
```
┌──────────────────────────────────┬─────────────┬────────────┬────────┐
│ Metric                           │ Current CFT │ Scoped CFT │ Change │
├──────────────────────────────────┼─────────────┼────────────┼────────┤
│ Total Permissions                │ 156         │ 47         │ ↓ 109  │
│ Wildcard Resource Permissions    │ 89          │ 12         │ ↓ 77   │
│ HIGH Findings                    │ 8           │ 0          │ ↓ 8    │
└──────────────────────────────────┴─────────────┴────────────┴────────┘

✅ Permission count reduced by 69.9%
✅ Wildcard resources reduced by 86.5%
✅ 8 high-risk actions eliminated
```

### `validate` - Dry-Run Validation

Validates the generated policy using the AWS IAM Policy Simulator (requires AWS credentials).

```bash
cohesity-iam-scoper validate --policy scoped-cft.json
cohesity-iam-scoper validate --policy scoped-cft.json --profile my-aws-profile --region us-west-2
```

### `parse-openapi` - Parse OpenAPI Specs

Extracts AWS-relevant endpoints from Cohesity v1/v2 OpenAPI specs.

```bash
cohesity-iam-scoper parse-openapi --spec cluster_v2_api.yaml
cohesity-iam-scoper parse-openapi --spec cluster_v1_api.yaml --output aws-endpoints.json
cohesity-iam-scoper parse-openapi --spec cluster_v2_api.yaml --no-filter-aws
```

## Supported Cohesity Workflows

| Workflow | Risk Level | Description |
|----------|-----------|-------------|
| AWS Source Registration | LOW | Discover EC2, RDS, S3, DynamoDB resources |
| EC2 VM Backup | MEDIUM | EBS snapshots, EC2 image backups |
| EC2 VM Restore / CloudSpin | HIGH | Instance recovery, cloud spin-up |
| RDS Backup | MEDIUM | RDS DB and Aurora cluster snapshots |
| RDS Restore | HIGH | Point-in-time and snapshot restore |
| RDS Backup S3 Staging | MEDIUM | Staging bucket for cross-account restores |
| DynamoDB Backup | LOW | On-demand backups and PITR exports |
| S3 Archive | MEDIUM | Long-term archival to Amazon S3 |
| Glacier Archive | LOW | S3 Glacier and Deep Archive |
| IAM Role Management | HIGH | Create/manage Cohesity IAM roles |
| SSM Operations | MEDIUM | App-consistent snapshot quiescing |
| CloudFormation Management | MEDIUM | Manage Cohesity CFT stacks |
| KMS Encryption | LOW | Customer-managed key encryption |

## Example: Generated Scoped Policy

For an EC2 backup workflow with the `CohesityManaged` tag condition:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2SnapshotCreate",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSnapshot",
        "ec2:CopySnapshot"
      ],
      "Resource": [
        "arn:aws:ec2:us-east-1:123456789012:volume/*",
        "arn:aws:ec2:us-east-1::snapshot/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:RequestTag/CohesityManaged": "true"
        }
      }
    },
    {
      "Sid": "EC2DiscoveryReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    }
  ]
}
```

## Project Structure

```
cohesity-iam-scoper/
├── README.md
├── requirements.txt
├── setup.py
├── cohesity_iam_scoper/
│   ├── cli.py                      # Main CLI interface (Click)
│   ├── parsers/
│   │   ├── openapi_parser.py       # Parse v1/v2 OpenAPI specs
│   │   └── cft_parser.py           # Parse and assess CFT templates
│   ├── mappers/
│   │   ├── permission_map.py       # Load AWS permission mappings
│   │   └── feature_detector.py     # Map selections → IAM permissions
│   ├── generators/
│   │   ├── policy_generator.py     # Generate raw IAM policy JSON
│   │   ├── cft_generator.py        # Generate CloudFormation templates
│   │   └── comparison.py           # Compare current vs. scoped
│   ├── validators/
│   │   └── dry_run.py              # IAM Policy Simulator validation
│   └── ui/
│       ├── questionnaire.py        # Interactive setup wizard
│       └── output.py               # Rich terminal output
├── data/
│   ├── aws_permission_map.json     # Cohesity feature → AWS IAM mappings
│   └── templates/
│       └── minimal_cft_template.json   # Minimal scoped CFT example
└── tests/
    ├── test_cft_parser.py
    ├── test_permission_mapper.py
    ├── test_policy_generator.py
    ├── test_comparator.py
    └── test_openapi_parser.py
```

## Security Best Practices

1. **Always use tag conditions** for EC2 and RDS operations to limit scope to Cohesity-managed resources only.

2. **Implement permissions boundaries** on Cohesity IAM roles to prevent privilege escalation:
   ```bash
   cohesity-iam-scoper configure
   # When asked "Use a permissions boundary?": Yes
   # Enter your boundary ARN: arn:aws:iam::123456789012:policy/CohesityBoundary
   ```

3. **Scope S3 permissions to specific buckets** rather than using wildcard patterns wherever possible:
   ```
   S3 bucket names: cohesity-prod-backup-us-east-1, cohesity-dr-bucket
   ```

4. **Restrict IAM role creation** to the `Cohesity*` namespace to prevent unauthorized role creation.

5. **Limit regions** to only the AWS regions where Cohesity actually operates.

6. **Use `validate`** to verify permissions before deploying to production.

## FAQ

**Q: Do I need to run `configure` before `generate`?**
A: Yes, `generate` requires a config file. Use `configure` for an interactive setup, or `init` to create a template you can edit manually.

**Q: Will the scoped policy break existing Cohesity functionality?**
A: The tool generates policies based on the workflows you select. If you're missing a workflow, re-run `configure`, add it, and regenerate.

**Q: Can I use this with multiple AWS accounts?**
A: Run the tool once per AWS account. Cross-account support via IAM role assumption is planned for a future release.

**Q: Does this require internet access or AWS connectivity?**
A: No, except for the `validate` command which calls the AWS IAM Policy Simulator.

**Q: How do I update the permission mappings as Cohesity adds new features?**
A: Update `data/aws_permission_map.json` with new feature entries. The schema is documented in that file.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run tests: `pytest tests/`
5. Submit a pull request

## Running Tests

```bash
# Install test dependencies
pip install -e .
pip install pytest

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_cft_parser.py -v
```

## License

Apache 2.0 - See LICENSE for details.
