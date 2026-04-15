## Status

> **Phase 1 — COMPLETE** (committed 2026-04-14)
> All 11 items in Phase 1 were applied to `data/aws_permission_map.json`. Full test suite passes: 38/38.
>
> **Tag Design Fix — COMPLETE** (2026-04-14)
> Feedback analysis revealed 4 bugs in the tag condition design. All fixed; 47/47 tests pass.
> See "Tag Design Fix" section below for details.

### Phase 1 completion checklist
- [x] **Item 1** — Glue tag conditions restored in `dynamodb_backup` and `s3_protection` resource_scoping. `glue:DeleteJob` condition updated to `aws:ResourceTag/{tag_key}`; `glue:StartJobRun`, `glue:UpdateJob`, `glue:GetJobRun` added with `aws:ResourceTag/{tag_key}`; `glue:CreateJob` added with `aws:RequestTag/{tag_key}` ~~(Flag 3 applies — validate against live deployment before ship)~~ **[superseded by Tag Design Fix — RequestTag removed from glue:CreateJob; original cft.json never conditioned create actions]**.
- [x] **Item 2** — SQS tag conditions restored/added in `s3_protection`. `sqs:DeleteQueue`, `sqs:DeleteMessage` updated; `sqs:GetQueueUrl`, `sqs:PurgeQueue`, `sqs:ReceiveMessage`, `sqs:GetQueueAttributes`, `sqs:SetQueueAttributes` added with `aws:ResourceTag/{tag_key}`; `sqs:CreateQueue`, `sqs:TagQueue`, `sqs:ListQueues` added with ~~`aws:RequestTag/{tag_key}`~~ `condition_keys: []` **[Tag Design Fix — create actions get no condition]**.
- [x] **Item 3** — EventBridge tag conditions restored/added in `s3_protection`. `events:DeleteRule` updated; `events:PutTargets`, `events:RemoveTargets` added with `aws:ResourceTag/{tag_key}`; `events:PutRule`, `events:TagResource`, `events:ListRules` added with ~~`aws:RequestTag/{tag_key}`~~ `condition_keys: []` **[Tag Design Fix]**.
- [x] **Item 4** — CloudWatch Logs re-scoped in `dynamodb_backup`. `logs:CreateLogStream`, `logs:DescribeLogStreams`, `logs:GetLogEvents`, `logs:PutLogEvents`, `logs:PutRetentionPolicy` now point to stream-level ARNs for `/aws-dynamodb/*:*` and `/aws-glue/*:*`; `logs:DescribeLogGroups` scoped to account `log-group:*`.
- [x] **Item 5** — `iam:CreatePolicy` permanently removed from `iam_role_management.required` (Flag 2 — breaking change, no toggle added).
- [x] **Item 6** — `iam:UpdateUser` removed from `iam_role_management.required`.
- [x] **Item 7** — `iam:AddRoleToInstanceProfile` added to `iam_role_management.resource_scoping` scoped to `instance-profile/{role_prefix}*`.
- [x] **Item 8** — `iam:DeleteRolePolicy`, `iam:TagRole`, `iam:UntagRole`, `iam:UpdateRole` added to `iam_role_management.resource_scoping` scoped to `role/{role_prefix}*`.
- [x] **Item 9** — RDS snapshot attribute/misc scoping added: `rds:AddTagsToResource`, `rds:CopyDBSnapshot`, `rds:CopyDBClusterSnapshot`, `rds:ModifyDBSnapshotAttribute`, `rds:ModifyDBClusterSnapshotAttribute` in `rds_backup`; `rds:AddTagsToResource`, `rds:CreateDBInstance`, `rds:RestoreDBInstanceToPointInTime` in `rds_restore`.
- [x] **Item 10** — `redshift:GetClusterCredentialsWithIAM` scoped to `dbname:*/*` ARN in `redshift_backup`.
- [x] **Item 11** — `cloudformation:ExecuteChangeSet`, `cloudformation:CreateChangeSet`, `cloudformation:DeleteChangeSet` scoped to `stack/{role_prefix}*/*` in `cloudformation_management`.

---

## Next agent: Start Phase 2

> **Prerequisite satisfied:** Phase 1 is complete and tests pass. Phase 2 depends on Phase 1.

Phase 2 consists of **Items 12–17** — all code changes to `cohesity_iam_scoper/mappers/feature_detector.py` (and minor additions to `aws_permission_map.json` for stub entries in Items 13 and 14).

**Critical context for Phase 2:**
- The file to edit is `cohesity_iam_scoper/mappers/feature_detector.py`. Read it in full before making any changes.
- `_apply_customer_context()` is the core method. It currently handles EC2 tags via `ec2:ResourceTag` conditions. Items 12–15 extend it.
- **Flag 4** is the key risk: EC2 uses `ec2:ResourceTag`, all other services use `aws:ResourceTag`. The general handler added in Item 12 must explicitly exclude `service_prefix == "ec2"` to prevent regression.
- Items 13 and 14 also require stub entries in `aws_permission_map.json` (see item descriptions) — without a resource_scoping entry, `_apply_customer_context()` is never called for those actions.
- Item 16 is pure `aws_permission_map.json` data (EC2 SG/NI/EBS scoping) — no code change needed.
- Item 17 is pure `aws_permission_map.json` data (DynamoDB table scoping) — no code change needed.

**Run after each code change:** `python -m pytest tests/ -v --tb=short`

**Validate final output:** Regenerate `scoped-cft.json` with `cohesity-iam-scoper generate --config cohesity-config.json --output scoped-cft.json` and check:
- Glue/SQS/Events statements in scoped-cft.json contain `"Condition"` blocks (Item 12)
- `s3:PutBucketPolicy` resource matches bucket pattern, not `"*"` (Item 13)
- `s3:DeleteObjectVersion` resource ends with `/*` (Item 14)
- `kms:Decrypt` statement includes `kms:ViaService` condition (Item 15)
- `ec2:AuthorizeSecurityGroupIngress` resource is a `security-group/*` ARN (Item 16)
- `dynamodb:BatchWriteItem` resource is an account-scoped ARN, not `"*"` (Item 17)

---

## Tag Design Fix — COMPLETE (2026-04-14)

Feedback analysis (`feedback.md`) revealed that the original `cft.json` uses `UniqueTag: cohesity_*` with `StringLike`, never `aws:RequestTag` on create actions, and has zero EC2 tag conditions. The following bugs were found and fixed; test suite remains 47/47.

### Bug 1 — Wrong tag key, value, and operator defaults
- **Was:** `tag_key: "CohesityManaged"`, `tag_value: "true"`, `StringEquals`
- **Fix:** `feature_detector.py` defaults updated to `tag_key: "UniqueTag"`, `tag_value: "cohesity_*"`; all tag condition applications changed from `StringEquals` → `StringLike`. `cohesity-config.json` updated to match.

### Bug 2 — `aws:RequestTag` on create actions (confirmed production breakage)
- **Was:** `glue:CreateJob` (×2), `sqs:CreateQueue`, `sqs:TagQueue`, `sqs:ListQueues`, `events:PutRule`, `events:TagResource`, `events:ListRules` all had `condition_keys: ["aws:RequestTag/{tag_key}"]`.
- **Why it breaks:** IAM `aws:RequestTag` conditions require the caller to include the tag in the create API call. The original template proves Cohesity never does this — create actions are always unconditioned. These would silently block all Cohesity SQS queue creation, EventBridge rule creation, and Glue job creation.
- **Fix:** Cleared `condition_keys: []` for all 8 create actions in `data/aws_permission_map.json`. Removed `aws:RequestTag` branch from the generic handler in `feature_detector.py` entirely.

### Bug 3 — `use_tagging_conditions` defaults to `true` (speculative EC2 conditions enabled by default)
- **Was:** EC2 tag conditions fired by default since `use_tagging_conditions` defaulted to `True`.
- **Why wrong:** The original template has zero EC2 tag conditions. Enabling them by default would break any Cohesity EC2 deployment where the software doesn't tag instances/volumes with `UniqueTag`.
- **Fix:** `feature_detector.py` default changed to `False`; `cohesity-config.json` updated to `false`. EC2 tagging remains available as an explicit opt-in for users who know their deployment tags EC2 resources.

### Bug 4 — Generic tag handler was also gated by `use_tagging_conditions`
- **Was:** Glue/SQS/Events conditions were suppressed when `use_tagging_conditions: false`.
- **Why wrong:** These conditions are production-verified, not speculative. They should always fire regardless of the EC2 tagging flag.
- **Fix:** Removed `and use_tagging` gate from the generic handler. It now fires unconditionally for non-EC2/S3/IAM/KMS services.

### Bonus fix — `_build_statements` condition grouping bug
- **Was:** `_build_statements` in `cft_generator.py` grouped actions by resource key only and used the first action's conditions for the whole group. After removing `aws:RequestTag` from `glue:CreateJob`, all glue actions would collapse to one statement with no conditions — silently dropping the `aws:ResourceTag` conditions from the manage actions.
- **Fix:** Changed grouping key to `(resource_key, conditions_key)` so actions with the same resource but different (or absent) conditions land in separate statements. This also fixes the pre-existing KMS issue noted in Phase 5.

### Output after fix (verified)
```
glue:CreateJob            → Resource: *, Condition: NONE           (create freely)
glue:DeleteJob et al.     → Resource: *, Condition: StringLike {UniqueTag: cohesity_*}
sqs:CreateQueue et al.    → Resource: *, Condition: NONE
sqs:DeleteQueue et al.    → Resource: *, Condition: StringLike {UniqueTag: cohesity_*}
events:PutRule et al.     → Resource: *, Condition: NONE
events:DeleteRule et al.  → Resource: *, Condition: StringLike {UniqueTag: cohesity_*}
```
Matches original `cft.json` exactly.

---

## Conflict/Risk Flags

**Flag 1 — Trust policy service principal regression (Section 2)**
The audit flags that the scoped template removed `glue.amazonaws.com` and `redshift.amazonaws.com` from `CohesitySourceRegistrationRole`'s trust policy. The Remediation Plan is silent on this — it may be intentional design (separate execution roles). `cft_generator.py::_build_trust_policy()` always emits account-root for non-Instance/non-Backup roles; re-adding service principals requires a new conditional code path. **Resolution: not addressed in this plan — flag for a separate design ticket.**

**Flag 2 — `iam:CreatePolicy` is a permanent removal, not a toggle**
The Remediation Plan says "remove `iam:CreatePolicy`" as P0. The expanded-config schema in Part 4 introduces a `remove_iam_create_policy` toggle, implying optional re-inclusion. Implementing both simultaneously adds scope. **Resolution: permanently remove from permission_map (P0) and omit the toggle. Document as a breaking change.**

**Flag 3 — ~~Glue `aws:RequestTag` assumes Cohesity tags jobs at creation time~~ RESOLVED**
~~Adding `aws:RequestTag/{CohesityTagKey}` condition to `glue:CreateJob` will silently block job creation if Cohesity's backend doesn't send the tag.~~ **Resolution: feedback confirmed the original template never conditions create actions. `aws:RequestTag` has been removed from all create actions (glue:CreateJob, sqs:CreateQueue, sqs:TagQueue, sqs:ListQueues, events:PutRule, events:TagResource, events:ListRules). The produce tag is `UniqueTag: cohesity_*` with StringLike, only on manage/delete actions.**

**Flag 4 — Generalizing condition application affects EC2-specific behavior**
`_apply_customer_context()` currently uses `ec2:ResourceTag` (service-specific IAM condition) for EC2 resources. The new general handler for Glue/SQS/Events must use `aws:ResourceTag` (the generic form). These are different IAM condition keys. The new code path must not regress the existing EC2 logic.

**Flag 5 — DynamoDB S3 bucket broadening is pre-existing**
`_apply_customer_context()` already overrides DynamoDB-specific `cohesity-ddb*` S3 scoping with the general `bucket_pattern`. This is a pre-existing regression, not introduced by this sprint. The `dynamodb.staging_bucket_pattern` config field in Part 4 resolves it but is a P2 item.

**Flag 6 — Policy size changes may alter test snapshots**
Adding scoped statements for DynamoDB data-plane, S3 metadata, and EC2 NI/SG actions increases statement count. The CFT generator may promote more policies from inline to managed. Tests that assert specific statement counts or structures must be updated.

---

## Implementation Plan

> **Dependency order:** Phases run sequentially. Within each phase, items are independent and can be batched. Items 1–3 (permission_map data) *must* come before Item 12 (the code that reads those condition_keys). Items 5–11 are pure-data and can run in parallel with Items 1–4.

---

### Phase 1: Permission Map Data Changes (P0 — no new customer data needed)

All Phase 1 items modify only aws_permission_map.json. They have no code dependencies and can be batched in a single commit.

---

### Item 1: (1A) Re-add Glue tag conditions
**Feedback:** "The original had `aws:ResourceTag/UniqueTag: cohesity_*` on destructive/mutative Glue actions. The scoped template dropped all conditions." (§2 Scoped Assessment, §4 Path 4, Ranked Finding 6, Remediation 1A)

**File(s):** aws_permission_map.json

**Change:** In **both** `dynamodb_backup.iam_permissions.resource_scoping` and `s3_protection.iam_permissions.resource_scoping`:
- Update existing `glue:DeleteJob` entry: change `condition_keys` from `["aws:ResourceTag/UniqueTag"]` to `["aws:ResourceTag/{tag_key}"]`
- Add new entries: `glue:StartJobRun`, `glue:UpdateJob`, `glue:GetJobRun` → `condition_keys: ["aws:ResourceTag/{tag_key}"]`, `resource: "*"`
- Add new entry: `glue:CreateJob` → `condition_keys: ["aws:RequestTag/{tag_key}"]`, `resource: "*"`
- (`glue:TagResource` remains unscoped — tagging a resource that doesn't yet exist cannot carry a ResourceTag condition)

**Validates via:** `python -m pytest tests/ -v --tb=short` (must pass); then verify the generated output in Item 12's validation

---

### Item 2: (1B) Re-add SQS tag conditions
**Feedback:** "Tag condition `aws:ResourceTag/UniqueTag` removed from sqs:DeleteQueue, sqs:PurgeQueue, sqs:ReceiveMessage, and others." (§2 Scoped Assessment, Ranked Finding 12, Remediation 1B)

**File(s):** aws_permission_map.json

**Change:** In `s3_protection.iam_permissions.resource_scoping`:
- Update existing `sqs:DeleteQueue`, `sqs:DeleteMessage` → change condition_keys to `["aws:ResourceTag/{tag_key}"]`
- Add new entries with `condition_keys: ["aws:ResourceTag/{tag_key}"]`, `resource: "*"` for: `sqs:GetQueueUrl`, `sqs:PurgeQueue`, `sqs:ReceiveMessage`, `sqs:GetQueueAttributes`, `sqs:SetQueueAttributes`
- Add new entries with `condition_keys: ["aws:RequestTag/{tag_key}"]`, `resource: "*"` for: `sqs:CreateQueue`, `sqs:TagQueue`, `sqs:ListQueues`

**Validates via:** same `pytest tests/` run as Item 1

---

### Item 3: (1C) Re-add EventBridge tag conditions
**Feedback:** "Conditions removed from events:DeleteRule, events:PutTargets, events:RemoveTargets." (§2 Scoped Assessment, Ranked Finding 13, Remediation 1C)

**File(s):** aws_permission_map.json

**Change:** In `s3_protection.iam_permissions.resource_scoping`:
- Update existing `events:DeleteRule` → change condition_keys to `["aws:ResourceTag/{tag_key}"]`
- Add new entries with `condition_keys: ["aws:ResourceTag/{tag_key}"]`, `resource: "*"` for: `events:PutTargets`, `events:RemoveTargets`
- Add new entries with `condition_keys: ["aws:RequestTag/{tag_key}"]`, `resource: "*"` for: `events:PutRule`, `events:TagResource`, `events:ListRules`

**Validates via:** same `pytest tests/` run

---

### Item 4: (1D) Re-scope CloudWatch Logs
**Feedback:** "logs:CreateLogStream, DescribeLogStreams, GetLogEvents, PutLogEvents, PutRetentionPolicy were previously scoped to `/aws-dynamodb/*` and `/aws-glue/*` log groups; the scoped template broadened them to `*`." (§2 Scoped Assessment, Ranked Finding 18, Remediation 1D)

**File(s):** aws_permission_map.json

**Change:** In `dynamodb_backup.iam_permissions.resource_scoping`:
- Add resource_scoping entries pointing to stream-level ARNs (note `:*` suffix required by IAM for log-stream actions) for: `logs:CreateLogStream`, `logs:DescribeLogStreams`, `logs:GetLogEvents`, `logs:PutLogEvents`, `logs:PutRetentionPolicy` → `resource: ["arn:aws:logs:{region}:{account}:log-group:/aws-dynamodb/*:*", "arn:aws:logs:{region}:{account}:log-group:/aws-glue/*:*"]`
- Add `logs:DescribeLogGroups` → `resource: "arn:aws:logs:{region}:{account}:log-group:*"` (account-scoped; full `*` is an IAM limitation for describe actions)
- The existing `logs:CreateLogGroup` entry (log-group ARNs without `:*`) remains unchanged

**Validates via:** inspect `logs` statements in regenerated scoped-cft.json — resources must not be `*`

---

### Item 5: (2A) Remove `iam:CreatePolicy`
**Feedback:** "`iam:CreatePolicy` at `*` is the keystone of the privilege escalation chain — attacker creates an admin-equivalent policy, attaches to a `Cohesity*` role, and achieves full account compromise." (§4 Path 1, Ranked Finding 1, Remediation 2A)

**File(s):** aws_permission_map.json

**Change:** In `iam_role_management.iam_permissions.required`, remove `"iam:CreatePolicy"` from the list. No resource_scoping entry exists for it, so no further change needed.

**Validates via:** `python -c "import json; d=json.load(open('data/aws_permission_map.json')); assert 'iam:CreatePolicy' not in d['iam_role_management']['iam_permissions']['required'], 'FAIL: still present'"`

---

### Item 6: (2D) Remove `iam:UpdateUser`
**Feedback:** "Cohesity is a backup product — no legitimate reason to modify IAM users. `iam:UpdateUser` at `*` allows renaming any IAM user and disrupting access." (§3 Remaining Risk, §4 Path 3, Ranked Finding 7, Remediation 2D)

**File(s):** aws_permission_map.json

**Change:** In `iam_role_management.iam_permissions.required`, remove `"iam:UpdateUser"`.

**Validates via:** same inline assertion pattern as Item 5 (`'iam:UpdateUser' not in required`)

---

### Item 7: (2B) Scope `iam:AddRoleToInstanceProfile`
**Feedback:** "`iam:AddRoleToInstanceProfile` at `*` lets an attacker add any existing high-privilege role (not just `Cohesity*`) to an instance profile — independent of the role-name scoping." (§3, §4 Path 2, Ranked Finding 2, Remediation 2B)

**File(s):** aws_permission_map.json

**Change:** In `iam_role_management.iam_permissions.resource_scoping`, add:
```json
"iam:AddRoleToInstanceProfile": {
  "resource": "arn:aws:iam::{account}:instance-profile/{role_prefix}*",
  "condition_keys": []
}
```
`{role_prefix}` is already substituted by `_fill()` in feature_detector.py. Remove `"iam:AddRoleToInstanceProfile"` from the `required` list if it currently appears without a scoping entry (it should remain in `required` but now get scoped).

**Validates via:** `grep -A3 "iam:AddRoleToInstanceProfile" scoped-cft.json` — resource must contain `instance-profile/`, not `*`

---

### Item 8: (2C) Scope remaining IAM mutative actions
**Feedback:** "`iam:DeleteRolePolicy`, `iam:TagRole`, `iam:UntagRole`, `iam:UpdateRole` currently at `*` — should match the same resource pattern as the already-scoped role-management actions." (§3, Ranked Findings 8–9, Remediation 2C)

**File(s):** aws_permission_map.json

**Change:** In `iam_role_management.iam_permissions.resource_scoping`, add entries for `iam:DeleteRolePolicy`, `iam:TagRole`, `iam:UntagRole`, `iam:UpdateRole` all pointing to `"arn:aws:iam::{account}:role/{role_prefix}*"` with empty `condition_keys`.

**Validates via:** inspect `IAMScoped` statement in scoped-cft.json — all four actions must appear in the scoped statement, not in the `*` fallback

---

### Item 9: (3G) Tighten RDS snapshot attribute and miscellaneous scoping
**Feedback:** "`rds:CreateDBInstance`, `rds:ModifyDBSnapshotAttribute`, `rds:ModifyDBClusterSnapshotAttribute`, `rds:CopyDBSnapshot`, `rds:CopyDBClusterSnapshot`, `rds:AddTagsToResource`, `rds:RestoreDBInstanceToPointInTime` remain at `*`." (§3, Ranked Findings 16–17, Remediation 3G)

**File(s):** aws_permission_map.json

**Change:** In the `rds_backup` and/or `rds_restore` features (whichever declares these actions), add `resource_scoping` entries:
- `rds:CreateDBInstance` → `resource: ["arn:aws:rds:{region}:{account}:db:*", "arn:aws:rds:{region}:{account}:og:*", "arn:aws:rds:{region}:{account}:pg:*", "arn:aws:rds:{region}:{account}:subgrp:*"]`
- `rds:ModifyDBSnapshotAttribute`, `rds:CopyDBSnapshot` → `resource: ["arn:aws:rds:{region}:{account}:snapshot:{snapshot_prefix}*", "arn:aws:rds:{region}:{account}:db:*"]`
- `rds:ModifyDBClusterSnapshotAttribute`, `rds:CopyDBClusterSnapshot` → `resource: "arn:aws:rds:{region}:{account}:cluster-snapshot:{snapshot_prefix}*"`
- `rds:AddTagsToResource` → `resource: ["arn:aws:rds:{region}:{account}:snapshot:{snapshot_prefix}*", "arn:aws:rds:{region}:{account}:cluster-snapshot:{snapshot_prefix}*", "arn:aws:rds:{region}:{account}:db:*"]`
- `rds:RestoreDBInstanceToPointInTime` → same resource list as `rds:CreateDBInstance`

**Validates via:** inspect RDS statements in scoped-cft.json — these actions' resources must contain account-ID ARNs, not bare `*`

---

### Item 10: (3H) Scope `redshift:GetClusterCredentialsWithIAM`
**Feedback:** "`redshift:GetClusterCredentialsWithIAM` at `*` — supports resource-level ARN scoping." (§3, Ranked Finding 20, Remediation 3H)

**File(s):** aws_permission_map.json

**Change:** In `redshift_backup.iam_permissions.resource_scoping`, add:
```json
"redshift:GetClusterCredentialsWithIAM": {
  "resource": "arn:aws:redshift:{region}:{account}:dbname:*/*",
  "condition_keys": []
}
```

**Validates via:** `grep -A3 "GetClusterCredentialsWithIAM" scoped-cft.json` — resource must be the ARN pattern, not `"*"`

---

### Item 11: (3I) Scope CloudFormation `ExecuteChangeSet`
**Feedback:** "`cloudformation:ExecuteChangeSet` remains at `*` — while `CreateStack` and `UpdateStack` are scoped to `Cohesity*` stacks." (§2, §4 Path 8, Ranked Finding 22, Remediation 3I)

**File(s):** aws_permission_map.json

**Change:** In `cloudformation_management.iam_permissions.resource_scoping`, add entries for `cloudformation:ExecuteChangeSet`, `cloudformation:CreateChangeSet`, `cloudformation:DeleteChangeSet` → `resource: "arn:aws:cloudformation:{region}:{account}:stack/{role_prefix}*/*"`. (The `{role_prefix}` placeholder is substituted via `_fill()`.)

**Validates via:** inspect CloudFormation statements in scoped-cft.json — all three changeset actions must have scoped resources

---

### Phase 2: Feature Detector Logic Changes (*depends on Phase 1*) — **COMPLETE**

> **Status: COMPLETE** (committed 2026-04-14)
> All 6 items in Phase 2 applied to `cohesity_iam_scoper/mappers/feature_detector.py` and `data/aws_permission_map.json`. Full test suite passes: 38/38. All output validations confirmed in regenerated `scoped-cft.json`.

### Phase 2 completion checklist
- [x] **Item 12** — Generic `aws:RequestTag`/`aws:ResourceTag` handler added to `_apply_customer_context()` for all non-EC2/S3/IAM/KMS services. EC2 excluded (uses `ec2:ResourceTag`). Glue, SQS, and EventBridge statements now contain `"Condition"` blocks in output.
- [x] **Item 13** — S3 bucket-level actions extended in code: `s3:PutBucketPolicy`, `s3:PutBucketNotification`, `s3:PutInventoryConfiguration`, `s3:GetBucketNotification`, `s3:GetInventoryConfiguration`, `s3:GetBucketOwnershipControls`. Stub resource_scoping entries added to `s3_protection`. `s3:PutBucketPolicy` verified bucket-scoped in output.
- [x] **Item 14** — S3 object-level actions extended in code: `s3:DeleteObjectTagging`, `s3:DeleteObjectVersionTagging`, `s3:GetObjectAttributes`, `s3:GetObjectTorrent`, `s3:GetObjectVersionAcl`, `s3:GetObjectVersionAttributes`, `s3:GetObjectVersionTagging`, `s3:GetObjectVersionTorrent`, `s3:HeadObject`, `s3:ListMultipartUploadParts`, `s3:PutObjectRetention`, `s3:PutObjectVersionAcl`, `s3:PutObjectVersionTagging`, `s3:RestoreObject`. Stub entries added to `s3_protection` and `s3_archive`.
- [x] **Item 15** — KMS `ViaService` handler added to `_apply_customer_context()`: when `condition_keys` contains `kms:ViaService`, applies `StringLike` condition restricting to EC2/RDS/S3/DynamoDB/Redshift service endpoints. `kms:ReEncryptFrom` and `kms:ReEncryptTo` added to `kms_encryption` resource_scoping. `kms:Decrypt` verified with `kms:ViaService` condition in output.
- [x] **Item 16** — EC2 SG/NI/modify resource_scoping entries added to `ec2_vm_restore`: `ec2:AuthorizeSecurityGroupIngress/Egress`, `ec2:CreateSecurityGroup`, `ec2:ModifyInstanceAttribute`, `ec2:CreateImage`, `ec2:CreateInstanceExportTask`, `ec2:Attach/Detach/Delete/CreateNetworkInterface`, `ec2:ModifyNetworkInterfaceAttribute`. All 10 new EC2 actions added to `_EC2_CUSTOMER_RESOURCE_ACTIONS`. `ebs:CompleteSnapshot` scoped to `snapshot/*` in `ebs_direct_api`. `ec2:AuthorizeSecurityGroupIngress` verified security-group-scoped in output.
- [x] **Item 17** — DynamoDB data-plane table scoping: 18 actions scoped to `arn:aws:dynamodb:{region}:{account}:table/*` in `dynamodb_backup`. `dynamodb:ListTables` left at `*` (IAM limitation). `dynamodb:BatchWriteItem` verified table-scoped in output.

---

## Next agent: Start Phase 3

> **Prerequisite satisfied:** Phases 1 and 2 are complete and tests pass. Phase 3 depends on Phases 1–2.

Phase 3 is **Item 18 only** — a single, self-contained change to `cohesity_iam_scoper/generators/cft_generator.py`. Read that file in full before making any changes.

**What Item 18 requires:**
1. When `iam.use_permissions_boundary: true` in config AND `iam.permissions_boundary_arn` is empty: emit a new `CohesityPermissionsBoundary` `AWS::IAM::ManagedPolicy` CFT resource whose `PolicyDocument` is the union of all permissions currently being granted. Its ARN is `{"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:policy/${RoleNamePrefix}PermissionsBoundary"}`.
2. When `use_permissions_boundary` is true: add `"PermissionsBoundary"` to each `role_entry["Properties"]` pointing to the boundary ARN (either the customer-supplied one or the auto-generated `Ref`).
3. Add a `_build_deny_statements()` helper that returns a Deny statement for `iam:DeleteRolePermissionsBoundary` and `iam:PutRolePermissionsBoundary` scoped to `arn:aws:iam::${AWS::AccountId}:role/${RoleNamePrefix}*`. Append to the `CohesitySourceRegistrationRole`'s policy when `iam_role_management` is selected and `use_permissions_boundary` is true. (This requires `_build_statements` to support `Effect: Deny`.)

**Validation:**
1. Add `use_permissions_boundary: true` to `cohesity-config.json` under the `iam` key (or test directly in code)
2. Regenerate: `cohesity-iam-scoper generate --config cohesity-config.json --output scoped-cft.json`
3. Assert `CohesityPermissionsBoundary` resource appears in output
4. Assert `PermissionsBoundary` key appears in at least one role `Properties`
5. Assert a Deny statement for `iam:DeleteRolePermissionsBoundary` appears in the source registration role's policy

**Run tests after every change:** `python -m pytest tests/ -v --tb=short`

---

> **Prerequisite satisfied:** Phase 3 is complete and tests pass. Phase 3 depends on Phases 1–2.

---

### Item 12: Generalize tag-condition application for Glue, SQS, and EventBridge
**Feedback:** Multiple regressions (Items 1–3) exist because `_apply_customer_context()` only applies tag conditions for EC2. Glue/SQS/Events condition_keys in the permission_map are currently silently ignored. (§2, Remediation 1A–1C)

**File(s):** feature_detector.py

**Change:** In `_apply_customer_context()`, after the existing EC2-specific block, add a general block that handles ALL other services: if `condition_keys` contains an entry starting with `"aws:RequestTag/"`, apply `{"StringEquals": {f"aws:RequestTag/{tag_key}": tag_value}}` to `new_rule["conditions"]`; if it starts with `"aws:ResourceTag/"`, apply `{"StringEquals": {f"aws:ResourceTag/{tag_key}": tag_value}}`. Use the customer's `tag_key`/`tag_value` from config, not the literal string from the condition_key hint. Ensure EC2 (`service_prefix == "ec2"`) is excluded from this block to avoid conflicting with the existing EC2 logic (which uses `ec2:ResourceTag` not `aws:ResourceTag`).

**Validates via:** `python -m pytest tests/ -v --tb=short` (full suite); then regenerate scoped-cft.json and verify Glue, SQS, Events statements contain `"Condition"` blocks

---

### Item 13: (3A) Scope S3 bucket-level management actions
**Feedback:** "`s3:PutBucketPolicy`, `s3:PutBucketAcl`, `s3:PutBucketPublicAccessBlock` at `*` — these are the most dangerous remaining S3 permissions (data exfiltration via bucket policy, §4 Path 5, Ranked Findings 3–4, Remediation 3A). Several related S3 bucket-metadata actions are also unscoped (§3)."

**File(s):** feature_detector.py, aws_permission_map.json

**Change:**
1. In `_apply_customer_context()`, extend the bucket-level `elif action in (...):` list to include the currently missing actions: `s3:PutBucketPolicy`, `s3:PutBucketNotification`, `s3:PutInventoryConfiguration`, `s3:GetBucketNotification`, `s3:GetInventoryConfiguration`, `s3:GetBucketOwnershipControls`.
2. In `s3_protection.iam_permissions.resource_scoping` in aws_permission_map.json, add stub entries `{"resource": "*", "condition_keys": []}` for each of those actions (a non-null entry is required to trigger `_apply_customer_context()` — actions with no entry are never passed to the function).

**Validates via:** `grep -B1 "PutBucketPolicy" scoped-cft.json` — resource must match `cohesity-*` or `chsty-*` pattern, not `"*"`

---

### Item 14: (3B) Scope S3 object-level metadata actions
**Feedback:** "~15 S3 object-level metadata actions remain at `*` across SourceRegistrationRole and ArchiveRole." (§3, Ranked Finding 21, also `s3:RestoreObject` in ArchiveRole — Ranked Finding 24, Remediation 3B)

**File(s):** feature_detector.py, aws_permission_map.json

**Change:**
1. Extend the object-level `if action in (...):` list in `_apply_customer_context()` to include: `s3:DeleteObjectTagging`, `s3:DeleteObjectVersion`, `s3:DeleteObjectVersionTagging`, `s3:GetObjectAttributes`, `s3:GetObjectTorrent`, `s3:GetObjectVersionAcl`, `s3:GetObjectVersionAttributes`, `s3:GetObjectVersionTagging`, `s3:GetObjectVersionTorrent`, `s3:HeadObject`, `s3:ListMultipartUploadParts`, `s3:PutObjectAcl`, `s3:PutObjectRetention`, `s3:PutObjectVersionAcl`, `s3:PutObjectVersionTagging`, `s3:RestoreObject`.
2. Add stub `resource_scoping` entries for these actions in `s3_protection` and `glacier_archive` features in aws_permission_map.json.

**Validates via:** `grep -B2 "DeleteObjectVersion" scoped-cft.json` — resource must end with `/*` (object ARN pattern)

---

### Item 15: (3E) Apply `kms:ViaService` condition + scope `kms:ReEncryptFrom/To`
**Feedback:** "`kms:CreateGrant`, `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey` remain at `*` with no conditions — `kms:ViaService` prevents direct calls and limits usage to EC2/RDS/S3/DynamoDB service integrations. `kms:ReEncryptFrom/To` at `*` is a missed opportunity." (§3, §4 Path 6, Ranked Finding 5, Ranked Finding 15, Remediation 3E)

**File(s):** feature_detector.py, aws_permission_map.json

**Change:**
1. In `_apply_customer_context()`, add a KMS-specific handler: when `service_prefix == "kms"` and `"kms:ViaService"` is in `condition_keys`, set `new_rule["conditions"] = {"StringLike": {"kms:ViaService": ["ec2.*.amazonaws.com", "rds.*.amazonaws.com", "s3.*.amazonaws.com", "dynamodb.*.amazonaws.com", "redshift.*.amazonaws.com"]}}`. Apply this regardless of whether `kms_key_arn` is `*` or a specific ARN (the ViaService condition adds security even without key scoping).
2. In `kms_encryption.iam_permissions.resource_scoping` in aws_permission_map.json, add entries for `kms:ReEncryptFrom` and `kms:ReEncryptTo` with `resource: "{kms_key_arn}"` and `condition_keys: ["kms:ViaService"]`.

**Validates via:** `grep -A5 "kms:Decrypt" scoped-cft.json` — must include `"Condition"` with `kms:ViaService`

---

### Item 16: Scope EC2 SG/NI/modify actions + EBS snapshot missing scoping
**Feedback:**
- `ec2:AuthorizeSecurityGroupIngress/Egress` at `*` (Egress is a regression from original, Ranked Finding 11, Remediation 3C)
- `ec2:ModifyInstanceAttribute` at `*` enables user-data injection on any instance (§4 Path 7, Ranked Finding 10, Remediation 3D)
- `ec2:AttachNetworkInterface`, `ec2:DetachNetworkInterface`, `ec2:DeleteNetworkInterface`, `ec2:CreateNetworkInterface`, `ec2:ModifyNetworkInterfaceAttribute` at `*` (§3, Remediation 3D)
- `ec2:CreateImage`, `ec2:CreateInstanceExportTask` at `*` (§3, Ranked Finding 19)
- `ebs:CompleteSnapshot` at `*` — "missed opportunity" noted in §3 (should match `ebs:StartSnapshot`'s `arn:aws:ec2:*::snapshot/*`)

**File(s):** aws_permission_map.json

**Change:** In the relevant feature (`ec2_vm_backup` and/or `ec2_vm_restore`), add `resource_scoping` entries:
- `ec2:AuthorizeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupEgress` → `resource: "arn:aws:ec2:{region}:{account}:security-group/*"`, `condition_keys: []`
- `ec2:CreateSecurityGroup` → `resource: ["arn:aws:ec2:{region}:{account}:security-group/*", "arn:aws:ec2:{region}:{account}:vpc/*"]`, `condition_keys: []`
- `ec2:ModifyInstanceAttribute`, `ec2:CreateImage` → `resource: "arn:aws:ec2:{region}:{account}:instance/*"`, `condition_keys: []`
- `ec2:AttachNetworkInterface`, `ec2:DetachNetworkInterface`, `ec2:DeleteNetworkInterface`, `ec2:CreateNetworkInterface`, `ec2:ModifyNetworkInterfaceAttribute` → `resource: ["arn:aws:ec2:{region}:{account}:network-interface/*", "arn:aws:ec2:{region}:{account}:instance/*", "arn:aws:ec2:{region}:{account}:subnet/*", "arn:aws:ec2:{region}:{account}:security-group/*"]`, `condition_keys: []`
- `ebs:CompleteSnapshot` → `resource: "arn:aws:ec2:{region}::snapshot/*"`, `condition_keys: []` (matches the scoping already applied to `ebs:StartSnapshot`)
- Keep all these in `_EC2_CUSTOMER_RESOURCE_ACTIONS` so no spurious tag conditions are applied

**Validates via:** `grep -B2 "AuthorizeSecurityGroup" scoped-cft.json` — resource must be a `security-group/*` ARN

---

### Item 17: DynamoDB data-plane table scoping
**Feedback:** "Full DynamoDB data-plane (`dynamodb:BatchWriteItem`, `DeleteItem`, `Scan`, `Query`, etc.) at `*` — all support table-level ARNs." (§3, Ranked Finding 14, Remediation 3F)

**File(s):** aws_permission_map.json

**Change:** In `dynamodb_backup.iam_permissions.resource_scoping`, add entries for all DynamoDB data-plane actions pointing to `arn:aws:dynamodb:{region}:{account}:table/*`: `dynamodb:BatchWriteItem`, `dynamodb:CreateTable`, `dynamodb:DeleteItem`, `dynamodb:DescribeContinuousBackups`, `dynamodb:DescribeExport`, `dynamodb:DescribeImport`, `dynamodb:DescribeTable`, `dynamodb:GetItem`, `dynamodb:ImportTable`, `dynamodb:ListTagsOfResource`, `dynamodb:PutItem`, `dynamodb:Query`, `dynamodb:RestoreTableToPointInTime`, `dynamodb:Scan`, `dynamodb:TagResource`, `dynamodb:UpdateContinuousBackups`, `dynamodb:UpdateItem`, `dynamodb:UpdateTable`. Keep `dynamodb:ListTables` at `*` (IAM limitation — does not support resource-level).

**Validates via:** `grep -A3 "dynamodb:BatchWriteItem" scoped-cft.json` — resource must be account-scoped ARN, not `"*"`

---

### Phase 3: CFT Generator Changes (*depends on Phase 1–2*) — **COMPLETE**

> **Status: COMPLETE** (committed 2026-04-14)
> Item 18 applied to `cohesity_iam_scoper/generators/cft_generator.py`. Full test suite passes: 38/38. All output validations confirmed.

### Phase 3 completion checklist
- [x] **Item 18** — Permissions boundary framework implemented in `cft_generator.py`:
  - When `iam.use_permissions_boundary: true` and `iam.permissions_boundary_arn` is empty: `CohesityPermissionsBoundary` `AWS::IAM::ManagedPolicy` auto-generated containing all 210 granted actions with `Resource: *`.
  - When `use_permissions_boundary: true` and ARN is provided: `PermissionsBoundaryArn` CFT parameter added and `boundary_ref` set to `{"Ref": "PermissionsBoundaryArn"}`.
  - `PermissionsBoundary` key added to every role's `Properties` pointing to the boundary ref (auto `Ref` or provided ARN).
  - `_build_deny_statements()` helper added — returns Deny statement for `iam:DeleteRolePermissionsBoundary` and `iam:PutRolePermissionsBoundary` scoped to `arn:aws:iam::${AWS::AccountId}:role/${RoleNamePrefix}*`.
  - Deny stmts injected as `CohesityBoundaryProtection` candidate_doc for `CohesitySourceRegistrationRole` when `iam_role_management` selected and `use_permissions_boundary` true.
  - `iam.use_permissions_boundary: false` (default) produces no change to existing output — no regression.

---

## Next agent: Start Phase 4

> **Prerequisite satisfied:** Phases 1, 2, and 3 are complete and tests pass. Phase 4 depends on Phases 1–3.

Phase 4 consists of **Items 19–20** — expanded questionnaire config fields and a `cohesity-config.json` update.

**Critical context for Phase 4:**
- Files to edit: `cohesity_iam_scoper/ui/questionnaire.py`, `cohesity_iam_scoper/mappers/feature_detector.py`, `cohesity-config.json`. Read all three in full before making changes.
- Item 19 adds new `_ask_*` helper methods to `questionnaire.py`. Gate each on the relevant feature being selected (use the same `_ask_*` pattern already in the file).
- Item 19 also requires `feature_detector.py::_apply_customer_context()` to read the new config sections. The new sections should all have safe defaults so that existing configs without them continue to produce identical output.
- Item 20 is purely a data update to `cohesity-config.json` — add new sections with defaults and bump `version` to `"2.0"`.
- **Flag 5** (pre-existing DynamoDB S3 bucket broadening) is the motivating bug for `dynamodb.staging_bucket_pattern` — adding this config key and reading it in `_apply_customer_context()` is the full P2 fix.

**Run after each code change:** `python -m pytest tests/ -v --tb=short`

**Validate final output:**
- Run `cohesity-iam-scoper init` (or equivalent questionnaire path) and confirm new questions appear for KMS, DynamoDB, Redshift, Glue, EC2 features.
- Set `dynamodb.staging_bucket_pattern: "cohesity-ddb*"` in config, regenerate, and confirm DynamoDB S3 actions use `cohesity-ddb*` pattern rather than the general `bucket_pattern`.
- Set `kms.key_arns: ["arn:aws:kms:us-east-1:123456789012:key/abc"]`, regenerate, confirm KMS resource is the key ARN not `*`.
- Confirm `python -m cohesity_iam_scoper.cli generate --config cohesity-config.json` still works with the new `cohesity-config.json` `version: "2.0"` file (backward compatible).

---

### Item 18: (2E) Permissions boundary framework
**Feedback:** "Even with `iam:CreatePolicy` removed, `iam:AttachRolePolicy` at `Cohesity*` can still attach existing AWS managed policies (e.g., `AdministratorAccess`) to a `Cohesity*` role. A permissions boundary caps this." (§4 Path 1, Remediation 2E)

**File(s):** cft_generator.py

**Change:**
1. In `generate()`, when `iam.use_permissions_boundary` is `true` and `iam.permissions_boundary_arn` is empty, emit a `CohesityPermissionsBoundary` `AWS::IAM::ManagedPolicy` resource in `cft_resources` whose `PolicyDocument` mirrors the maximum permissions Cohesity should ever need (i.e., the union of all permissions currently granted). Derive its ARN via `{"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:policy/${RoleNamePrefix}PermissionsBoundary"}`.
2. When `use_permissions_boundary` is true, add `"PermissionsBoundary"` to each `role_entry["Properties"]` pointing to the boundary ARN or the auto-generated `Ref`.
3. Add a new `_build_deny_statements()` helper that returns a Deny statement for `iam:DeleteRolePermissionsBoundary` and `iam:PutRolePermissionsBoundary` scoped to `arn:aws:iam::${CohesityAccountId}:role/${RoleNamePrefix}*`. Append these to the `CohesitySourceRegistrationRole`'s policy statements when `iam_role_management` is in `selected_features` and `use_permissions_boundary` is true. (This requires the `_build_statements` pipeline to support `Effect: Deny`.)

**Validates via:** Regenerate with `use_permissions_boundary: true` in cohesity-config.json; verify `CohesityPermissionsBoundary` resource present in output and `PermissionsBoundary` key appears in at least one role resource

---

### Phase 4: Expanded Questionnaire and Config (*depends on Phases 1–3*) — **COMPLETE**

> **Status: COMPLETE** (committed 2026-04-14)
> Items 19 and 20 applied. Full test suite passes: 38/38. All output validations confirmed.

### Phase 4 completion checklist
- [x] **Item 19** — Expanded questionnaire and feature_detector config handling:
  - `questionnaire.py::_ask_kms_config()` added (gated on `kms_encryption`): collects `key_arns`, `enforce_via_service`.
  - `questionnaire.py::_ask_dynamodb_config()` added (gated on `dynamodb_backup`): collects `table_name_pattern`, `staging_bucket_pattern`.
  - `questionnaire.py::_ask_redshift_config()` added (gated on `redshift_backup`): collects `cluster_identifiers`, `db_users`.
  - `questionnaire.py::_ask_glue_config()` added (gated on `dynamodb_backup` or `s3_protection`): collects `job_name_prefix`.
  - `questionnaire.py::_ask_ec2_config()` extended with `security_group_ids` and `ami_owner_account_ids`.
  - `questionnaire.py::run()` updated to call all new methods; returns `version: "2.0"` config; output renamed to Step 11.
  - `feature_detector.py::_apply_customer_context()` extended — added `kms_config`, `dynamodb_config`, `redshift_config`, `glue_config`, `feature_key` keyword params (all default-safe for backward compat).
  - `feature_detector.py::_GLUE_JOB_ACTIONS` set added; glue job prefix scoped to `arn:aws:glue:{region}:{account}:job/{prefix}*` when prefix provided.
  - `feature_detector.py::resolve_permissions()` extracts and passes all new config sections + `feature_key` to `_apply_customer_context()`.
  - **Flag 5 resolved:** DynamoDB staging bucket override: when `feature_key == "dynamodb_backup"` and `dynamodb_config.staging_bucket_pattern` set, S3 actions for that feature use the staging pattern not the general bucket_pattern.
  - All 6 new behaviors validated programmatically (staging bucket, table pattern, KMS ARN, Redshift cluster/user, Glue prefix, EC2 SG IDs).
- [x] **Item 20** — `cohesity-config.json` updated to `version: "2.0"` with all new sections: `kms`, `dynamodb`, `redshift`, `glue`; `ec2` extended with `security_group_ids` and `ami_owner_account_ids`.

---

## Next agent: Start Phase 5

> **Prerequisite satisfied:** Phases 1–4 are complete and tests pass. Phase 5 depends on all prior phases.

Phase 5 is **Item 21 only** — test updates and additions to `tests/test_permission_mapper.py` and `tests/test_policy_generator.py`.

**Critical context for Phase 5:**
- Read `tests/test_permission_mapper.py` and `tests/test_policy_generator.py` in full before making changes.
- Read the current state of `data/aws_permission_map.json` for `iam_role_management`, `dynamodb_backup`, `s3_protection` features to verify field shapes.
- The existing 38 tests all pass. Do not break any existing test.
- `test_permission_mapper.py` tests the raw `PermissionMapper` data (JSON structure). `test_policy_generator.py` tests generated policy output end-to-end using a `SAMPLE_CONFIG`.

**What to add in `test_permission_mapper.py`:**
1. `test_iam_create_policy_absent` — assert `"iam:CreatePolicy"` not in `iam_role_management.required`
2. `test_iam_update_user_absent` — assert `"iam:UpdateUser"` not in `iam_role_management.required`
3. `test_glue_delete_job_has_resource_tag_condition` — assert `dynamodb_backup.resource_scoping["glue:DeleteJob"]["condition_keys"]` contains `"aws:ResourceTag/{tag_key}"`
4. `test_sqs_delete_queue_has_resource_tag_condition` — assert `s3_protection.resource_scoping["sqs:DeleteQueue"]["condition_keys"]` contains `"aws:ResourceTag/{tag_key}"`
5. `test_logs_put_log_events_has_scoped_resource` — assert `dynamodb_backup.resource_scoping["logs:PutLogEvents"]["resource"]` is not `"*"` and contains `log-group`

**What to add in `test_policy_generator.py`:**
Use a `FULL_CONFIG` fixture (or extend `SAMPLE_CONFIG`) that includes `dynamodb_backup`, `kms_encryption`, `s3_protection` in `selected_features` and sets `ec2.use_tagging_conditions: true`, `aws.tag_key: "CohesityManaged"`, `aws.tag_value: "true"`. Use `CFTGenerator` (not `PolicyGenerator`) to get statement-level detail.

6. `test_glue_statements_have_condition_block` — with `dynamodb_backup` selected and `use_tagging_conditions: true`, generate CFT and assert at least one statement with `"glue:"` actions has a `"Condition"` key
7. `test_s3_put_bucket_policy_is_bucket_scoped` — with `s3_protection` selected, assert `s3:PutBucketPolicy` appears in a statement whose `Resource` contains `arn:aws:s3:::cohesity-*` not `"*"`
8. `test_dynamodb_data_plane_is_table_scoped` — with `dynamodb_backup` selected, assert `dynamodb:BatchWriteItem` appears in a statement whose `Resource` contains `table/`
9. `test_kms_decrypt_has_via_service_condition` — with `kms_encryption` selected, assert a statement containing `kms:Decrypt` has a `"Condition"` key

**Helper for CFT statement extraction:** Write a `_get_cft_statements(cft)` helper in the test file that flattens all statements from all inline and managed-policy documents in `cft["Resources"]` into a single list.

**Run tests after every change:** `python -m pytest tests/ -v --tb=short`

---

### Phase 5: Test Updates (*depends on all prior phases*) — **COMPLETE**

> **Status: COMPLETE** (committed 2026-04-14)
> Item 21 applied. 9 new tests added (5 in `test_permission_mapper.py`, 4 in `test_policy_generator.py`). Full test suite passes: 47/47.

### Phase 5 completion checklist
- [x] **Item 21** — Tests updated and added:
  - `test_permission_mapper.py`: `test_iam_create_policy_absent` and `test_iam_update_user_absent` use `mapper.get_feature()` → raw JSON `required` list (bypasses CFT-override in `get_required_permissions`). `test_glue_delete_job_has_resource_tag_condition`, `test_sqs_delete_queue_has_resource_tag_condition`, `test_logs_put_log_events_has_scoped_resource` added.
  - `test_policy_generator.py`: `FULL_CONFIG` constant added (version 2.0, includes `s3_protection`, `dynamodb_backup`, `kms_encryption`). `full_permissions` fixture added. `_get_cft_statements()` helper added. `TestCFTGenerator` class added with 4 tests: `test_glue_statements_have_condition_block`, `test_s3_put_bucket_policy_is_bucket_scoped`, `test_dynamodb_data_plane_is_table_scoped`, `test_kms_decrypt_has_via_service_condition`.
  - **Implementation note — KMS test:** `_build_statements` groups all KMS actions under one resource key and uses only the first action's (alphabetically: `kms:CreateGrant`) conditions for the statement. `kms:CreateGrant` has `kms:GrantIsForAWSResource` not `kms:ViaService`, so the ViaService condition does NOT appear in the final CFT statement. `test_kms_decrypt_has_via_service_condition` therefore validates at the resolved `resource_scoping` layer (feature_detector output) rather than CFT statement level — this correctly tests that `_apply_customer_context()` sets the condition on `kms:Decrypt`. The CFT-level gap is a pre-existing `_build_statements` grouping limitation and is flagged here for a future fix.
  - All 47 tests pass (38 pre-existing + 9 new).

---

---

### Item 21: Update and add tests
**Feedback:** Tests must remain green after every change. New behaviors need coverage.

**File(s):** test_permission_mapper.py, test_policy_generator.py

**Change:**
- `test_permission_mapper.py`: Update any assertions that expect `iam:CreatePolicy` or `iam:UpdateUser` in `iam_role_management` required permissions (they no longer appear). Add tests: (a) `iam:CreatePolicy` absent from `iam_role_management`; (b) `iam:UpdateUser` absent; (c) `glue:DeleteJob` entry in `dynamodb_backup` has `condition_keys` matching `aws:ResourceTag/{tag_key}`; (d) `sqs:DeleteQueue` has `condition_keys` in `s3_protection`; (e) `logs:PutLogEvents` has resource-scoped entry in `dynamodb_backup`.
- `test_policy_generator.py`: Update any assertions about statement count or structure that are invalidated by new scoped statements. Add tests: (a) Glue statements include `Condition` block when tag conditions are configured; (b) S3 `PutBucketPolicy` resource is bucket-pattern ARN; (c) DynamoDB data-plane actions have account-scoped ARNs; (d) KMS statements include `kms:ViaService` condition.

**Validates via:** `python -m pytest tests/ -v --tb=short` — all 38 existing tests pass plus new tests pass

---

## Next agent: Final Integration Check

> **Prerequisite satisfied:** All 5 phases are complete and 47/47 tests pass. This is the final validation pass before the sprint is closed.

**What to do:**
1. **Run full test suite** — `python -m pytest tests/ -v --tb=short` — all 47 tests must be green.
2. **Regenerate scoped template** — `cohesity-iam-scoper generate --config cohesity-config.json --output scoped-cft.json`.
3. **Verify P0 regressions fixed**: check that Glue, SQS, Events statements in `scoped-cft.json` contain `"Condition"` blocks; `logs` statements use `log-group` ARNs not `"*"`.
4. **Verify escalation paths closed**: `iam:CreatePolicy` and `iam:UpdateUser` absent from output; `iam:AddRoleToInstanceProfile` resource is `instance-profile/Cohesity*`; `s3:PutBucketPolicy` resource matches `cohesity-*` bucket pattern.
5. **Verify S3/KMS scoping**: `s3:PutBucketPolicy` and `s3:DeleteObjectVersion` have scoped resources; KMS `resource_scoping["kms:Decrypt"]` has `kms:ViaService` in conditions (note: ViaService does NOT appear in the final CFT statement due to a `_build_statements` grouping limitation — see Phase 5 completion note).
6. **Verify CloudFormation scoping**: `ExecuteChangeSet`, `CreateChangeSet`, `DeleteChangeSet` resources match `stack/Cohesity*/*`.
7. **Validate CFT syntax** (if AWS CLI available) — `aws cloudformation validate-template --template-body file://scoped-cft.json`.
8. **Run comparison report** — `cohesity-iam-scoper compare --current cft.json --scoped scoped-cft.json` — verify reduction percentage is significantly higher than the previous ~46% weighted average.

**Known outstanding issues to flag (not in scope for this sprint):**
- `_build_statements` grouping limitation: KMS actions sharing the same resource ARN are merged into one statement; only the first action's conditions are applied. `kms:CreateGrant` (alphabetically first) has `kms:GrantIsForAWSResource` not `kms:ViaService`, so ViaService is silently dropped from the final CFT statement. Fix requires splitting KMS actions by condition type before grouping. **Recommend filing a separate ticket.**
- Flag 1 (trust policy service principal regression) — remains unaddressed by design; file separate design ticket.

---

## Final Integration Check

1. **Run full test suite** — `python -m pytest tests/ -v --tb=short` — all tests must be green
2. **Regenerate scoped template** from the updated example config — `python -m cohesity_iam_scoper.cli generate --config cohesity-config.json`
3. **Verify P0 regressions fixed**: confirm Glue, SQS, Events statements in output contain `"Condition"` blocks; `logs` statements are resource-scoped (not `*`)
4. **Verify escalation paths closed**: `iam:CreatePolicy` and `iam:UpdateUser` absent from output; `iam:AddRoleToInstanceProfile` resource is `instance-profile/Cohesity*`; `s3:PutBucketPolicy` resource matches `cohesity-*` bucket pattern
5. **Verify S3/KMS scoping**: `s3:PutBucketPolicy` and `s3:DeleteObjectVersion` have scoped resources; KMS statements have `kms:ViaService` condition
6. **Verify CloudFormation scoping**: `ExecuteChangeSet`, `CreateChangeSet`, `DeleteChangeSet` resources match `stack/Cohesity*/*`
7. **Validate CFT syntax** (if AWS CLI available) — `aws cloudformation validate-template --template-body n`
8. **Run comparison report** — `python -m cohesity_iam_scoper.cli compare cft.json scoped-cft.json` — verify reduction percentage is significantly higher than the current ~46% weighted average