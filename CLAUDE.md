# CLAUDE.md — Appliance V1FS (Service Gateway File Scanner)

## Project Overview

AWS-deployed TrendAI Service Gateway virtual appliance(s) configured as file security scanners. Files arriving in S3 trigger a Lambda function that scans them via the File Security SDK over gRPC. The Service Gateway is a multi-purpose appliance from TrendAI (formerly Trend Micro).

## Branding

Trend Micro has rebranded to **TrendAI**. Always use "TrendAI" in user-facing text (README, docs, comments). Internal references in code, SDK package names, and config values may still use the old naming — do not change those.

## Architecture

```
S3 (Ingest) → SQS Queue → Lambda Scanner → gRPC/TLS:443 → Service Gateway EC2 → Clean or Quarantine Bucket
                 └→ DLQ (after 5 failures) → Remediation Lambda (backoff → retry/discard)
```

### Components

| Resource | Purpose |
|---|---|
| VPC (10.2.0.0/16) | 2 public subnets, 2 private subnets, dual NAT Gateways |
| Service Gateway EC2 Instances | TrendAI appliance(s) running File Security scanner, fixed fleet |
| EC2 Instance Connect Endpoint | SSH access to Service Gateway via EICE tunnels |
| Scanner Lambda (zip + layer) | Scans files via gRPC SDK, triggered by SQS |
| SQS Queue + DLQ | S3 event notifications drive scan jobs |
| DLQ Remediation Lambda | Re-queues DLQ messages with exponential backoff (60s/300s/900s) |
| Reconciliation Lambda | Re-queues orphaned ingest files every 5 minutes |
| S3 Buckets | Ingest (source), Clean (passed), Quarantine (malware/oversize) — DeletionPolicy: Retain |
| CloudWatch Dashboard | 30-widget dashboard with queue health, scan performance, detection analysis |
| CloudWatch Alarms + SNS | DLQ alarm, queue age alarm |
| Secrets Manager | Vision One API key, SG registration token, SG CA cert |
| Provisioner Lambda (zip + layer) | Automates SG registration, hostname, cert extraction; watchdog for version monitoring |
| Watchdog Schedule | EventBridge rule triggers provisioner every 15 min to check SG versions |
| CodeBuild | Builds scanner + provisioner Lambda layers and code zips from GitHub |

### Service Gateway Fleet

SG appliances are plain **EC2 instances** (no ASG, no auto-scaling, no auto-replacement):

- **`ServiceGatewayCount`** (default 3, max 3) EC2 instances launched from a shared launch template
- **EventBridge provisioning:** EC2 state-change events trigger the provisioner Lambda when instances reach `running` state
- **Provisioner** registers each SG with Vision One, sets hostname, extracts CA cert (cert works before FS install — it's from the AMI's nginx, not the scanner pod)
- **Watchdog** runs every 15 minutes — checks scanner versions, re-extracts cert on version change
- **No auto-replacement** — if an SG dies, CloudWatch alarm notifies; admin decides what to do
- **Dynamic Discovery** — scanner Lambda discovers SGs via EC2 tags (`appliance-v1fs:stack`), refreshes every 60 seconds
- Each SG gets a unique hostname from its CloudFormation Name tag (`FSVA-AWS-01`, `-02`, `-03`)

### Multi-Channel gRPC

The `ChannelsPerSG` parameter (1-8, default 2) opens multiple gRPC channels per SG. **2 channels is the optimal setting** — it doubles throughput per SG without overloading nginx. 4 channels causes RST_STREAM errors under load.

## Deployment Flow

1. **Commit and push** code to GitHub (`arcaniusdev/appliance-v1fs`)
2. **Create deploy bucket** if needed: `aws s3 mb s3://appliance-v1fs-deploy-886436954261` (teardown deletes it)
3. **Deploy stack:** Upload template to S3, then `aws cloudformation create-stack --stack-name appliance-v1fs-N` via S3 template URL (template >51KB)
4. Stack creates all infrastructure; CodeBuild pulls from GitHub, builds scanner + provisioner layers, zips AWS CLI runtime to S3
5. EC2 instances launch → EventBridge fires EC2 state-change event → provisioner Lambda triggered for each instance
6. Provisioner connects via EICE SSH tunnel, waits for admin readiness, sets OS hostname (from CloudFormation Name tag), sets clish endpoint name, registers SG with Vision One using registration token from Secrets Manager, verifies registration, extracts CA cert via sgowner `openssl s_client`, patches nginx `proxy-body-size` to `MaxFileSizeMB` for large file scanning, tags instance as `appliance-v1fs:provisioned=true`
7. **Manual step:** Install File Security on all SGs via Vision One console (Workflow and Automation → Service Gateway Management → Manage Services)
8. Scanning begins — files arriving in the ingest S3 bucket trigger SQS messages, which invoke the scanner Lambda

### How Scanning Works

1. S3 object-created event notification sends a message to the SQS scan queue
2. Lambda SQS event source mapping invokes the scanner Lambda (batch size 1)
3. Scanner Lambda discovers running SGs by calling `ec2:DescribeInstances` filtered by `appliance-v1fs:stack={StackName}` tag, caches results for 60 seconds
4. Scanner creates gRPC channels to each SG's private IP on port 443, using the CA cert from Secrets Manager and the Vision One API key for authentication (`ChannelsPerSG` channels per SG)
5. Scanner downloads the file from S3, selects a healthy channel (circuit breaker skips channels with 3+ consecutive failures for 60s), sends the file via `amaas.grpc.scan_buffer`
6. Based on scan result: file is copied to the clean or quarantine S3 bucket with a `ScanResult` tag, then deleted from ingest
7. Scan result is written to the CloudWatch audit log group
8. If scan fails, the SQS message becomes visible again after the visibility timeout, retried up to 5 times, then sent to the DLQ

**Always use `--disable-rollback`** on `create-stack` so failures can be inspected in place.

## File Structure

```
project/
├── CLAUDE.md                        # This file
├── appliance-v1fs.yaml              # CloudFormation template (all infrastructure)
├── buildspec.yml                    # CodeBuild: scanner + provisioner layers and code zips
├── .claude/commands/
│   └── teardown.md                  # /teardown slash command for full account cleanup
├── docs/
│   ├── service-gateway-reference.md # TrendAI Service Gateway documentation
│   ├── comparison-report.html       # EKS vs Appliance comparison report
│   └── icap-interface-report.html   # Undocumented ICAP interface research
├── app/
│   ├── requirements.txt             # visionone-filesecurity
│   └── scanner.py                   # Lambda handler: SQS → S3 download → gRPC scan → route
└── lambda/
    └── provisioner/
        ├── requirements.txt         # paramiko (AWS CLI v2 downloaded from S3 at runtime)
        ├── handler.py               # EC2 provisioner + watchdog handler
        ├── ssh_helper.py            # Paramiko-based clish SSH interaction
        ├── eice_tunnel.py           # EICE tunnel management for SSH
        └── cfn_response.py          # CloudFormation response helper
```

## Scanner Lambda (Zip-Based)

The scanner Lambda is a **zip deployment with a Lambda layer**, not a container image:
- **Runtime:** python3.12
- **Handler:** scanner.handler
- **Code:** `scanner.py` uploaded to S3 by CodeBuild
- **Layer:** `visionone-filesecurity` + gRPC dependencies compiled for Amazon Linux x86_64
- **Timeout:** 900s (Lambda maximum, matches SQS visibility timeout)
- **Memory:** 3008 MB (Lambda max; supports large file scanning via gRPC)
- **VPC-attached:** Private subnets (to reach Service Gateway on port 443)
- **SQS trigger:** Batch size 1, `ReportBatchItemFailures` for fast retry
- **SG Discovery:** Discovers running SGs dynamically via EC2 tags (`appliance-v1fs:stack`), refreshes every 5 minutes
- **Circuit breaker:** Per-channel failure tracking with cooldown

### nginx Body Size Patch

The default nginx configmap has `proxy-body-size: 10m`, blocking gRPC scans >10MB. The provisioner patches this to match the `MaxFileSizeMB` parameter (default 500MB) during initial provisioning, and the watchdog re-applies it every 15 minutes in case a scanner pod update reverts the configmap. The same parameter controls the gRPC channel limits in the scanner Lambda.

## Provisioner Lambda (Zip-Based)

The provisioner Lambda is a zip deployment with a Lambda layer (paramiko only):
- **Non-VPC:** Runs outside the VPC, connects to SGs via EICE SSH tunnels
- **AWS CLI v2:** Downloaded from S3 to `/tmp` at cold start (not bundled in layer — too large, symlinks break, PyInstaller botocore can't be stripped)
- **Provisioning:** Triggered by EventBridge EC2 state-change events when instances reach `running`. Registers SG, sets hostname, extracts CA cert
- **Root access:** Uses sgowner via KB article KA-0014380 (generate RSA key, install via `configure verify cli support`, SSH as sgowner)
- **Cert extraction:** Via sgowner `openssl s_client` to localhost:443 — works before FS install (cert is from the AMI's nginx)
- **Hostname:** Sets OS hostname via `hostnamectl set-hostname` through sgowner SSH (Vision One uses OS hostname, not clish endpoint name)
- **Watchdog:** Runs every 15 minutes via EventBridge schedule, checks scanner versions on running instances, re-extracts cert if version changes


## Performance (Tested)

### c5.2xlarge (8 vCPU, 16 GB) — Optimal Instance Size

The c5.4xlarge is massively overprovisioned. At peak load, scanner pod uses 26m CPU and 1.7GB memory of 16 vCPU / 32GB available. **c5.2xlarge handles the same throughput at half the cost.**

### With 2 Channels Per SG (Optimal)

| Config | Throughput | Queue Backlog at 20M/day Rate |
|---|---|---|
| 1 SG (c5.2xlarge, 2 ch) | ~110 files/sec (~9.5M/day) | Builds backlog |
| 3 SGs (c5.2xlarge, 2 ch) | ~231 files/sec (~20M/day) | **Zero backlog** |

### Key Performance Facts
- Scanner pod doesn't autoscale (no HPA on virtual appliance, single replica)
- Bottleneck is gRPC concurrency in nginx, not CPU/memory
- `TM_AM_MAX_HANDLER: 32` concurrent scan handlers in the scanner pod
- Scanner pod has 4 containers: scanner, uploader, connector, redis
- gRPC scan cache exists (`TM_AM_SCAN_CACHE=true`) unlike earlier documentation

### Performance vs eks-v1fs

| Factor | EKS | Appliance |
|---|---|---|
| Peak throughput ceiling | ~750K/min | ~13K/min (3 SGs, 2 ch) |
| Cost at 20M/day spike | ~$5,000/mo | ~$1,820/mo (3× c5.2xlarge) |
| Cost at 2M/day baseline | ~$690/mo | ~$1,020/mo |
| Scale-up speed | 30-60s | Instant (Lambda) |
| Operational complexity | High | Low |

## Undocumented ICAP Interface

The scanner pod exposes an ICAP service on port 1344 (documented only for the containerized scanner, not the virtual appliance). See `docs/icap-interface-report.html` for full research. **Not used in production** — ICAP has size limitations and requires iptables DNAT workarounds that don't persist across reboots.

## SSH & CLI Gotchas

- **Default credentials:** Username `admin`, default password `V1SG@2021` (key pair auth used instead)
- **clish space handling:** Use `paramiko.invoke_shell()` with character-by-character sends (10ms delay). Never use `exec_command()` for clish.
- **clish has no shell escape** — `execute shell` doesn't work. For shell access, use sgowner root path.
- **Root access:** Per KB KA-0014380: generate RSA 4096 key, `configure verify cli support {base64_pubkey}` via admin clish, SSH as `sgowner`, `sudo su -` for root.
- **MicroK8s Calico CNI doesn't support hostPort or NodePort binding** — no kube-proxy running.
- **Admin readiness:** Retries every 15s until admin commands accepted.
- **`configure verify plat`** shows pod status. Look for `sg-sfs-scanner` with `Running`.
- **SSM Agent not supported** — use EICE for SSH.
- **Same self-signed cert on all SG AMI instances** — CN `*.sgi.xdr.trendmicro.com`.
- **Vision One uses OS hostname** — set via `hostnamectl set-hostname` through sgowner SSH, not `configure endpoint` via clish. The clish endpoint command sets a different field.

## Secrets (Secrets Manager)

| Secret | Purpose | Protected |
|---|---|---|
| `appliance-v1fs/vision-one-api-key` | V1FS SDK API key | **Never delete** |
| `appliance-v1fs/sg-registration-token` | SG registration JWT | **Never delete** |
| `appliance-v1fs/sg-ca-cert` | SG self-signed CA cert (PEM) | Auto-managed |

## CloudFormation Parameters

| Parameter | Default | Description |
|---|---|---|
| `PrimaryAZ` | us-east-1a | Primary availability zone |
| `SecondaryAZ` | us-east-1b | Secondary availability zone |
| `ServiceGatewayHostname` | FSVA-AWS | Hostname prefix (auto-numbered) |
| `ServiceGatewayCount` | 3 | Number of SGs (1-3, always running) |
| `ServiceGatewayInstanceType` | c5.4xlarge | c5.2xlarge or c5.4xlarge |
| `ChannelsPerSG` | 1 | gRPC channels per SG (1-8, use 2) |
| `MaxFileSizeMB` | 500 | Max file size in MB for gRPC scanning (nginx + channel limit) |
| `PMLEnabled` | true | Predictive Machine Learning for gRPC scans |
| `SmartFeedbackEnabled` | true | Scan telemetry to TrendAI |

## Stack Naming & Template Size

Always use incrementing stack names: `appliance-v1fs-1`, `appliance-v1fs-2`, etc. Never reuse.

The template exceeds 51,200 bytes — must deploy via S3 URL, not `--template-body`. Use a deploy bucket:
```bash
aws s3 cp appliance-v1fs.yaml s3://{deploy-bucket}/template.yaml
aws cloudformation create-stack --template-url https://s3.amazonaws.com/{deploy-bucket}/template.yaml ...
```

**Do not upload templates to the ingest bucket** — S3 event notifications will trigger the scanner on them.

## BuildSpec (CodeBuild)

CodeBuild pulls from GitHub and:
1. Builds scanner Lambda layer (visionone-filesecurity + gRPC) → uploads to S3 deploy bucket
2. Zips scanner.py → uploads to S3 deploy bucket
3. Builds provisioner Lambda layer (paramiko only) → uploads to S3 deploy bucket
4. Downloads AWS CLI v2, zips the `dist/` directory → uploads `awscli-runtime.zip` to S3 deploy bucket
5. Zips provisioner code (handler.py, ssh_helper.py, eice_tunnel.py) → uploads to S3 deploy bucket

### AWS CLI v2 in Lambda — Lessons Learned

The AWS CLI v2 binary **cannot be bundled in a Lambda layer** due to multiple issues:
- **Lambda doesn't preserve symlinks** from layer zips — the `bin/aws`, `v2/current` symlinks all break
- **PyInstaller botocore data can't be stripped** — the binary has an internal index; removing service model directories causes random `'s3'`, `'codedeploy'` errors
- **Unstripped, it exceeds the 250MB layer limit**

**Solution:** CodeBuild uploads the AWS CLI `dist/` directory as `awscli-runtime.zip` to S3. The provisioner's `eice_tunnel.py` downloads and extracts it to `/tmp/awscli/dist/aws` on cold start. This bypasses all layer limitations.

**YAML gotcha:** The `--only-binary=:all:` pip flag contains colons that YAML interprets as tags. The command must be quoted.

## Critical Rules

- **Never download malware locally** — use S3 server-side copy only
- **Never store credentials in files** — use Secrets Manager
- **S3 event notifications encode spaces as `+`** — scanner uses `urllib.parse.unquote_plus()`
- **gRPC requires `ssl_target_name_override`** — cert CN doesn't match IP
- **gRPC max file size is `MaxFileSizeMB`** (default 500MB) — nginx body size and gRPC channel limits set from this parameter
- **Always use `--disable-rollback`** on stack creation for debuggability
- **Vision One API is read-only for Service Gateway** — only GET endpoint exists
- **Always ask before making Vision One API changes** — shared platform
- **Disconnect old SGs from Vision One before registering new ones**
- **S3 buckets have DeletionPolicy: Retain** — survive stack deletion
- **Malware sample bucket is protected** — never delete `eks-v1fs-malware-samples-886436954261`
- **Scanner Lambda needs `s3:ListBucket`** — without it, S3 returns AccessDenied instead of NoSuchKey for missing objects, causing infinite retries
- **Lambda concurrency limit** — account default was 10, increased to 1000 via Service Quotas
- **CloudWatch Logs throttling** — cache the logs client and create log streams once per execution environment, not per scan
- **Census (`TM_AM_CENSUS`) is file prevalence tracking, not Predictive Machine Learning**
- **SQS API attribute is `ApproximateNumberOfMessages`** — not `ApproximateNumberOfMessagesVisible` (that's the CloudWatch metric name, different from the API attribute)
- **VPC-attached Lambda ENI cleanup takes 15-20 minutes** — this is the main bottleneck during stack deletion. The scanner Lambda's ENIs in the VPC take AWS a long time to release
- **Deploy bucket is deleted during teardown** — must recreate `appliance-v1fs-deploy-886436954261` before next deploy
- **File Security install requires running instances** — install FS after stack creation while SGs are running

## Service Gateway AMI (BYOL v3.0.27)

Product code: `a4akc5rzzt5b2a9trld1chlf`. AMI IDs mapped per region in CloudFormation `Mappings`. Optimal instance type: **c5.2xlarge** (8 vCPU, 16 GB) — meets TrendAI minimal spec at half the cost of c5.4xlarge.
