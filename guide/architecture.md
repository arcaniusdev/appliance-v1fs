# Architecture Guide

## Components

| Resource | Purpose |
|---|---|
| VPC (10.2.0.0/16) | 2 public subnets, 2 private subnets, dual NAT Gateways |
| Service Gateway EC2 Instances | TrendAI appliance(s) running File Security scanner, fixed fleet |
| EC2 Instance Connect Endpoint | SSH access to Service Gateway via EICE tunnels |
| Scanner Lambda (zip + layer) | Scans files via gRPC SDK, triggered by SQS |
| SQS Queue + DLQ | EventBridge fan-in routes S3 events to SQS; DLQ after 5 failures |
| DLQ Remediation Lambda | Re-queues DLQ messages with exponential backoff (60s/300s/900s) |
| Reconciliation Lambda | Backfills unscanned files on new bucket enrollment, re-scans stale files |
| S3 Ingest Bucket | Default ingest bucket with EventBridge enabled (DeletionPolicy: Retain) |
| S3 Quarantine Bucket | Central quarantine for malicious files from all accounts (DeletionPolicy: Retain) |
| EventBridge Bus Policy | Org-wide policy allowing any org account to forward events |
| CloudWatch Dashboard | Queue health, scan performance, detection analysis, cross-account breakdown |
| CloudWatch Alarms + SNS | DLQ alarm, queue age alarm |
| Secrets Manager | Vision One API key, SG registration token, SG CA cert |
| Provisioner Lambda (zip + layer) | Automates SG registration, hostname, cert extraction; watchdog for version monitoring |
| Watchdog Schedule | EventBridge rule triggers provisioner every 15 min to check SG versions |
| CodeBuild | Builds scanner + provisioner Lambda layers and code zips from GitHub |

## Service Gateway Fleet

SG appliances are plain **EC2 instances** (no ASG, no auto-scaling, no auto-replacement):

- **`ServiceGatewayCount`** (default 3, max 3) EC2 instances launched from a shared launch template
- **EventBridge provisioning:** EC2 state-change events trigger the provisioner Lambda when instances reach `running` state
- **Provisioner** registers each SG with Vision One, sets hostname, extracts CA cert (cert works before FS install — it's from the AMI's nginx, not the scanner pod)
- **Watchdog** runs every 15 minutes — checks scanner versions, re-extracts cert on version change
- **No auto-replacement** — if an SG dies, CloudWatch alarm notifies; admin decides what to do
- **Dynamic Discovery** — scanner Lambda discovers SGs via EC2 tags (`appliance-v1fs:stack`), refreshes every 60 seconds
- Each SG gets a unique hostname from its CloudFormation Name tag (`FSVA-AWS-01`, `-02`, `-03`)

## Multi-Channel gRPC

Workers open 2 gRPC channels per SG (hardcoded). This doubles throughput per SG without overloading nginx. Testing showed 3+ channels causes imbalance (79/21% traffic split) and 4 channels causes RST_STREAM errors under load.

## Scanner Lambda

The scanner Lambda is a **zip deployment with a Lambda layer**, not a container image:
- **Runtime:** python3.12
- **Handler:** scanner.handler
- **Layer:** `visionone-filesecurity` + gRPC dependencies compiled for Amazon Linux x86_64
- **Timeout:** 900s (Lambda maximum, matches SQS visibility timeout)
- **Memory:** 3008 MB (supports large file scanning via gRPC)
- **VPC-attached:** Private subnets (to reach Service Gateway on port 443)
- **SQS trigger:** Batch size 1, `ReportBatchItemFailures` for fast retry
- **SG Discovery:** Discovers running SGs dynamically via EC2 tags, refreshes every 60 seconds
- **Circuit breaker:** Per-channel failure tracking with cooldown (3 failures = 60s cooldown)

## How Scanning Works

1. S3 object-created event → EventBridge → SQS scan queue (any bucket with EventBridge enabled)
2. Lambda SQS event source mapping invokes the scanner Lambda (batch size 1)
3. Scanner discovers running SGs by calling `ec2:DescribeInstances` filtered by `appliance-v1fs:stack={StackName}` tag
4. Scanner creates gRPC channels to each SG's private IP on port 443, using CA cert and Vision One API key from Secrets Manager
5. Scanner downloads the file from S3 (using cross-account assumed-role credentials if needed), selects a healthy channel, sends the file via `amaas.grpc.scan_buffer`
6. Based on scan result:
   - **Clean:** file is tagged in place with `ScanResult=Clean` and `ScanTimestamp={ISO 8601}`, left in the source bucket
   - **Malicious:** file is copied to the central quarantine bucket at `{account_id}/{bucket}/{key}` with tags (`ScanResult=Malware`, `ScanTimestamp`, `SourceAccount`, `SourceBucket`), then deleted from the source bucket. Malware names are in the CloudWatch audit log, not in S3 tags (S3 tag values don't support all characters in malware names).
7. Scan result is written to the CloudWatch audit log group (includes `sourceAccount` field)
8. For cross-account scans, audit log is also written to a log group in the customer account
9. If scan fails, the SQS message becomes visible again after the visibility timeout, retried up to 5 times, then sent to the DLQ

## Enrolling Additional Buckets (Same Account)

Any S3 bucket in the same account can be enrolled for scanning by enabling EventBridge notifications:
```bash
aws s3api put-bucket-notification-configuration --bucket BUCKET_NAME \
  --notification-configuration '{"EventBridgeConfiguration":{}}'
```
No other configuration needed — the EventBridge rule catches all S3 Object Created events.

## Multi-Account Scanning

Cross-account buckets can be enrolled for scanning. The scanner account maintains a central quarantine bucket; clean files are tagged in place in the customer's account, malicious files are moved to quarantine.

### Enrollment Flow

1. Admin provides customer with: `enrollment.yaml`, scanner account ID, scanner Lambda role ARN
2. Customer deploys `enrollment.yaml` in their account (must be in the same AWS Organization)
3. Customer tags S3 buckets with `v1fs:scan = true` — tag-watcher Lambda enables EventBridge automatically
4. Scanning begins. First file triggers backfill of any existing unscanned files in the bucket.

### Scanner Account Components

- `OrgId` parameter — org-wide EventBridge bus policy allows any org account to forward events (auto-detected if not set)
- **EventBridge Bus Policy** — CloudFormation resource with `aws:PrincipalOrgID` condition
- **Quarantine Bucket** — central quarantine, keys prefixed with `{account_id}/{bucket}/`
- **Reconciliation Lambda** — backfills unscanned files on new bucket enrollment, re-scans files older than `RescanAfterDays`

### Customer Account Components (enrollment.yaml)

- `ScannerAccessRole` (fixed name: `appliance-v1fs-scanner-access`) — IAM role trusting the scanner Lambda, with S3 read/delete/tag/list permissions and CloudWatch Logs write
- `EventBridgeForwardRole` + `ForwardScanEventsRule` — forwards S3 Object Created events to scanner account's default bus
- `TagWatcherLambda` — enables EventBridge on buckets tagged `v1fs:scan = true`
- `ScanAuditLogGroup` — `v1fs-scan-audit` log group for customer-side audit trail (90-day retention)
- `CustomerDashboard` — CloudWatch dashboard with scan KPIs, detection analysis, performance metrics

### Pre-Populated Enrollment Template

The scanner stack auto-generates a pre-populated enrollment template (with scanner account ID and Lambda role ARN baked in) and uploads it to the deploy bucket. Customers can deploy it with zero parameters. The template URL is available in the stack outputs (`EnrollmentTemplateURL`).

## Secrets (Secrets Manager)

| Secret | Purpose | Protected |
|---|---|---|
| `appliance-v1fs/vision-one-api-key` | V1FS SDK API key | **Never delete** |
| `appliance-v1fs/sg-registration-token` | SG registration JWT | **Never delete** |
| `appliance-v1fs/sg-ca-cert` | SG self-signed CA cert (PEM) | Auto-managed |

## Service Gateway AMI (BYOL v3.0.27)

Product code: `a4akc5rzzt5b2a9trld1chlf`. AMI IDs mapped per region in CloudFormation `Mappings`. Minimum spec: **8 CPUs, 12 GB memory** (TrendAI minimal image). Optimal instance type: **c5.2xlarge** (8 vCPU, 16 GB) — meets minimum spec at lowest cost.
