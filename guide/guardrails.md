# Guardrails

Critical rules, constraints, and gotchas for working with this project.

## Security

- **Never download malware locally** — use S3 server-side copy only
- **Never store credentials in files** — use Secrets Manager
- **Cross-account S3 uses assumed-role credentials** — never use the Lambda's native S3 client for remote bucket operations
- **Cross-account role name is fixed** — `appliance-v1fs-scanner-access` in every enrolled account. Scanner derives role ARN from account ID in the event.

## S3 & EventBridge

- **EventBridge passes S3 object keys URL-encoded** — spaces as `%20`, not `+`
- **EventBridge only fires for new objects** — existing files in a bucket when EventBridge is enabled won't trigger scans. The reconciliation Lambda handles backfill on first enrollment.
- **Do not upload templates to the ingest bucket** — EventBridge will route them to the scanner
- **S3 tag values have restricted characters** — letters, numbers, spaces, and `+ - = . _ : / @` only. No commas, asterisks, pipes, semicolons, etc. Malware names are stored in CloudWatch audit logs, not S3 tags, for this reason.

## gRPC & Scanning

- **gRPC requires `ssl_target_name_override`** — cert CN doesn't match IP
- **gRPC max file size is `MaxFileSizeMB`** (default 500MB) — nginx body size and gRPC channel limits set from this parameter
- **2 gRPC channels per SG is optimal** — 4 channels causes RST_STREAM errors under load
- **Census (`TM_AM_CENSUS`) is file prevalence tracking, not Predictive Machine Learning**

## CloudFormation & Deployment

- **Always use `--disable-rollback`** on stack creation for debuggability
- **Always use incrementing stack names** — `appliance-v1fs-1`, `appliance-v1fs-2`, etc. Never reuse.
- **Template exceeds 51,200 bytes** — must deploy via S3 URL, not `--template-body`
- **Deploy bucket is deleted during teardown** — must recreate before next deploy
- **File Security install requires running instances** — install FS after stack creation while SGs are running
- **VPC-attached Lambda ENI cleanup takes 15-20 minutes** — main bottleneck during stack deletion
- **CloudFormation conditions can't reference custom resource outputs** — if a resource's creation depends on a runtime-discovered value (e.g., auto-detected OrgId), use a custom resource Lambda to manage that resource via API calls rather than a conditional CloudFormation resource.
- **Custom resource Lambdas need `s3:ListBucket`** — `s3:GetObject` alone returns `AccessDenied` (not `NoSuchKey`) when the key doesn't exist if `ListBucket` is missing, making errors confusing.

## Provisioner & Service Gateway

- **SG registration tokens expire** — generate a fresh token from Vision One console for each deployment. No public API exists for SG tokens.
- **EventBridge provisioner race condition** — EC2 instances may reach `running` state before the EventBridge rule is fully active. If provisioning doesn't trigger, manually invoke the provisioner Lambda.
- **Disconnect old SGs from Vision One before registering new ones**
- **Vision One API is read-only for Service Gateway** — only GET endpoint exists
- **Single EICE tunnel per SG** — consolidate all SSH operations into one tunnel to avoid repeated subprocess/WebSocket overhead
- **Provisioner role needs `ec2:DescribeInstanceConnectEndpoints`** — required by the AWS CLI for EICE tunnel setup. Without it, the tunnel subprocess fails with `UnauthorizedOperation`.

## Lambda

- **Lambda max memory is 3008 MB** — not 3072 (AWS rounds down to multiples of 64)
- **Scanner Lambda needs `s3:ListBucket`** — without it, S3 returns AccessDenied instead of NoSuchKey for missing objects, causing infinite retries
- **CloudWatch Logs throttling** — cache the logs client and create log streams once per execution environment, not per scan
- **Lambda layers don't preserve symlinks** — use S3 download for large binaries (AWS CLI v2)
- **CodeBuild runs once at stack creation** — code changes after stack creation require manual rebuild + Lambda code update
- **Lambda warm environments persist old code** — after updating function code, warm execution environments keep running the old version. Force cold starts by updating function configuration (e.g., add/change an environment variable). Just updating the code is not sufficient for immediate rollout.
- **Stack updates require enrollment.yaml in the stack's deploy bucket** — the enrollment template builder custom resource reads from the stack's own deploy bucket (auto-named by CloudFormation), not the shared deploy bucket used for template upload.

## Reconciliation

- **Backfill** — on first scan from a new bucket, reconciliation lists all existing objects and queues unscanned files. Tracks backfilled buckets in SSM `/appliance-v1fs/backfilled-buckets`.
- **Rescan** — files with `ScanTimestamp` older than `RescanAfterDays` are re-queued. Files newer than the rescan threshold are skipped for efficiency.
- **Cross-account buckets tracked in SSM** — `/appliance-v1fs/cross-account-buckets` JSON mapping, auto-populated by scanner on first cross-account event.
- **Same-account buckets tracked in SSM** — `/appliance-v1fs/enrolled-buckets`, auto-populated by scanner, pruned by reconciliation.

## SQS

- **SQS API attribute is `ApproximateNumberOfMessages`** — not `ApproximateNumberOfMessagesVisible` (that's the CloudWatch metric name, different from the API attribute)
