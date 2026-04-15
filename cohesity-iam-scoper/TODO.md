we need to add to the cohesity-config.json. Cohesity has access to EBS Direct APIs, and we need to add permisisons for them as optional in the CohesitySourceRegistrationRole - 

---

## Phase 2: IAM Access Analyzer — Ground-Truth Permission Capture

**Goal:** Replace or validate CFT-derived permission lists with call-graph data captured from actual Cohesity runs, so `cft.json` itself can be kept up to date.

### Why this is needed
`cft.json` is Cohesity's published template but it may lag behind newer features or omit permissions that are only needed in specific configurations (cross-account, encrypted volumes, etc.). IAM Access Analyzer generates policies from actual CloudTrail events — it's the only way to know with certainty what Cohesity calls.

### Steps

1. **Setup sandbox account with permissive policy + CloudTrail**
   - Enable CloudTrail in a dedicated AWS sandbox account (log all management events)
   - Assign Cohesity's IAM roles an initial permissive policy (`AdministratorAccess` or a broad `*` allow) so no calls fail during testing

2. **Run each Cohesity workflow end-to-end**
   - For each feature in `cft_policy_feature_map.json`, run a complete cycle (backup + restore or archive + retrieve)
   - Note the CloudTrail time window for each run

3. **Generate policy via IAM Access Analyzer**
   - AWS Console → IAM → Access Analyzer → Generate policy
   - Select the CloudTrail trail and the time window for the test run
   - Download the generated policy for each role (`CohesitySourceRegistrationRole`, `CohesityArchiveRole`, etc.)

4. **Diff against cft.json**
   - Use `cohesity-iam-scoper analyze cft.json` output as baseline
   - Actions in Access Analyzer output but missing from CFT → add to the appropriate inline policy in `cft.json`
   - Actions in CFT but absent from every Access Analyzer run → flag as potentially unused (but do not remove without confirming)

5. **Update cft.json and regenerate**
   - Commit changes to `cft.json`
   - `PermissionMapper` will automatically pick them up on next run (no changes to `aws_permission_map.json` needed)

### Optional: iamlive for faster per-feature iteration
[iamlive](https://github.com/iann0036/iamlive) intercepts AWS SDK calls in real time without needing CloudTrail propagation delay.
- Run `iamlive --mode proxy --output-file captured.json` alongside Cohesity
- Useful for testing a single feature in isolation (e.g. just DynamoDB backup)
- Output can be diffed directly against a single CFT inline policy

### Coverage tracking

| Feature | Workflow tested | CloudTrail window | Verified |
|---------|----------------|-------------------|----------|
| EC2 fleet backup | ec2_vm_backup | | ☐ |
| EC2 restore / CloudSpin | ec2_vm_restore | | ☐ |
| EBS Direct API | ebs_direct_api | | ☐ |
| RDS backup | rds_backup | | ☐ |
| RDS restore | rds_restore | | ☐ |
| RDS DB Connect | rds_db_connect | | ☐ |
| RDS S3 staging | rds_staging_s3 | | ☐ |
| S3 protection | s3_protection | | ☐ |
| S3 archive | s3_archive | | ☐ |
| Glacier archive | glacier_archive | | ☐ |
| DynamoDB backup | dynamodb_backup | | ☐ |
| Redshift backup | redshift_backup | | ☐ |
| KMS encryption | kms_encryption | | ☐ |
| SSM (app-consistent) | ssm_operations | | ☐ |

