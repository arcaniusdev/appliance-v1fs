# Service Gateway Vision One File Security Scanner

Malware scanning on AWS, deployed the way TrendAI supports it. Two CloudFormation templates stand up [TrendAI Vision One File Security](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-file-security-intro-origin) running on **Service Gateway virtual appliances** — and a complete S3 scanning pipeline where files uploaded to a bucket are automatically scanned and routed to stay put (clean) or move to quarantine (malicious), based on the verdict.

The scanner is the stock TrendAI appliance; everything around it — networking, provisioning, the worker fleet, queues, buckets, IAM — deploys from the templates.

**📘 [The POC Guide](POC-GUIDE.md)** is the full walkthrough: Vision One account setup, click-by-click deployment, verification, success criteria, Java SDK integration, architecture, and teardown. This README is the overview.

## What is Vision One File Security?

Vision One File Security is TrendAI's malware scanning service for files. It uses multiple detection engines — pattern matching, heuristics, and predictive machine learning (PML) — to identify threats in files of any type.

In this project the scanner runs **inside a Service Gateway virtual appliance** — a stock TrendAI Marketplace AMI (Rocky Linux + MicroK8s) on which you install the File Security service. Scanning applications talk to the appliance over gRPC to scan files, and the appliance phones home to Vision One for threat-intelligence updates and to report results.

Files are scanned **locally within your VPC** — they are never uploaded to an external service; only scan metadata (verdicts, threat names) goes to Vision One.

## Supported by design

This stack runs the appliance the way TrendAI documents and supports, and keeps every deviation deliberate and minimal:

- **The appliance is the unmodified Marketplace AMI.** We don't rebuild or repackage it. Scanning uses the **documented gRPC-over-TLS scanner endpoint on port 443**.
- **Registration uses the documented clish `register` command**; File Security is installed the documented way (from the Vision One console).
- **Provisioning uses TrendAI's documented root path** (KB-0014380) over SSH — see [Provisioning](#provisioning-the-watchdog). We deliberately do **not** depend on the appliance's pre-installed SSM agent, because the appliance firmware self-upgrade removes it.
- **Scan policy** (decompression limits) is configured the documented way — in the Vision One console.
- **The fleet is fixed EC2 instances**, scaled horizontally by a stack parameter — no ASG or autoscaling on the appliances (a single scanner pod per appliance is optimal; see [Scaling](#scaling)).

Every remaining deviation from a stock deployment is enumerated in the [Drift section of the POC guide](POC-GUIDE.md#13-drift-from-the-default-deployment).

## The two stacks

The scanning **service** and the reference **application** are separate stacks, so any application can use the scanners — the bundled worker fleet is just one consumer.

| Stack | Creates | Think of it as |
|---|---|---|
| `scanner.yaml` | VPC, 1–8 Service Gateway appliances, provisioner Lambda ("the watchdog"), secrets, VPC endpoints | The scanning **service** — reusable by any application |
| `worker.yaml` | Scan + quarantine buckets, SQS queue + DLQ, auto-scaling worker fleet, CloudWatch dashboard | A complete reference **application** driving the service |

The scanner stack exports its VPC and discovery tags; the worker stack imports them. To integrate your own application instead, deploy only the scanner stack and connect via the SDK — see [Connect your own application](#connect-your-own-application).

## How it works

```
┌──────────────────────────────────────────────────────────────────────────┐
│ VPC (private subnets)                                                      │
│                                                                            │
│  S3 Scan Bucket ──▶ SQS Queue ──▶ Worker Fleet ──gRPC/TLS :443──▶ Service  │
│  (event → SQS)          │         (EC2, async)                    Gateway  │
│                         ▼                          ┌──────────────┐ (1–8)  │
│                   DLQ (5 fails)                    │  scanner pod │        │
│                         │                          │  (MicroK8s)  │        │
│                  Lambda auto-retry                 └──────┬───────┘        │
│                  (backoff → discard)                      │ verdict        │
│                                              ┌────────────┼────────────┐   │
│                                            CLEAN   NOT-FULLY-SCANNED  MALWARE│
│                                              │            │            │   │
│                                              ▼            ▼            ▼   │
│                                        tag+leave    tag+leave    tag+copy  │
│                                        in bucket    (ScanResult=  to quar- │
│                                                     NotFully-     antine,  │
│                                                     Scanned)      delete   │
└──────────────────────────────────────────────────────────────────────────┘
        every verdict → CloudWatch audit log (one JSON line per scan)
```

| Step | What happens |
|---|---|
| **Ingest** | A file lands in the scan bucket. S3 sends an `ObjectCreated` event directly to the SQS queue (no EventBridge). |
| **Scan** | A worker long-polls the queue, downloads the file into memory, discovers the appliances by EC2 tag, and scans it via the File Security SDK over gRPC to one of them (round-robin). |
| **Route** | The worker tags the object with the verdict and, for malware, copies it to the quarantine bucket (server-side) and deletes the original. The SQS message is removed and a JSON audit record is written to CloudWatch. |

**Routing rules:**

| Verdict | Condition | Action |
|---|---|---|
| **Clean** | `scanResult == 0`, no scan errors | Tag `ScanResult=Clean` + `ScanTimestamp`, leave in the scan bucket |
| **Malicious** | `scanResult > 0` | Tag `ScanResult=Malware`, server-side copy to the quarantine bucket, delete the original |
| **Not fully scanned** | `scanResult == 0` **and** a decompression limit was hit (`foundErrors`) | Tag `ScanResult=NotFullyScanned`, leave in the scan bucket — **never** marked Clean |
| **Skipped (too large)** | File exceeds `MaxFileSizeMB` (default 500) | Tag `ScanResult=SkippedTooLarge`, left in place (not downloaded) |

A file that hit a decompression limit was **not fully inspected**, so treating it as clean would be unsafe — it's tagged `NotFullyScanned` and left for an operator to decide (raise the limits in the console, or handle by policy).

### The scanner application (worker fleet)

The worker is a single ~430-line Python file (`app/scanner.py`) — small enough to read in one sitting and adapt with confidence.

- **Async, single event loop** (`amaas.grpc.aio` + `aiobotocore`) — one small instance holds many scans in flight; the synchronous SDK leaked OS threads under load, the async path is steady.
- **Direct-to-appliance, discovered by EC2 tag** — no load balancer (an ALB hit RESOURCE_EXHAUSTED; an NLB coalesced onto one appliance). One reused gRPC handle per appliance; round-robin across them; re-discovered every 60 s.
- **Capacity-derived concurrency** — `appliances × 32 handlers × 1.5`, enforced with a semaphore, so scaling the fleet retunes the workers automatically.
- **Visibility heartbeat** — extends the SQS message during long scans; shortens it to ~30 s on failure for fast retry. DLQ after 5 receives, with a Lambda that re-drives with backoff.
- **Graceful SIGTERM** — drains in-flight scans before exit (safe with auto-scaling).
- **TLS by default** — connects to the documented gRPC/TLS endpoint on 443; see [TLS and certificates](#tls-and-certificates).

Set nothing special to use it, or skip `worker.yaml` entirely and connect your own app to the scanner stack.

### Provisioning (the watchdog)

A small Lambda (`provisioner-<stack>`) runs every 15 minutes and owns the appliance lifecycle, so there's no manual appliance setup. Per appliance it: sets the hostname, registers with Vision One, waits for the File Security scanner pod, then hardens TLS ciphers, extracts the appliance CA certificate to Secrets Manager, patches the nginx upload limit if needed, and tags the instance's state.

All of this runs **over SSH via TrendAI's documented root path** (KB-0014380), not the SSM agent:

- **`admin` clish** — authenticated with the EC2 launch key pair (CloudFormation stores its private key in SSM Parameter Store), for `configure endpoint`, `register`, cipher hardening, `show version`, and pod-status checks.
- **`sgowner` root** — a key the provisioner generates each run and authorizes through `admin` clish (`configure verify cli support`), for `hostnamectl`, `sudo microk8s kubectl`, and `openssl` cert extraction.

**Why SSH, not the SSM agent:** the Service Gateway firmware self-upgrades on first boot, and that upgrade removes/disables the pre-installed SSM agent (it goes `ConnectionLost` and a reboot doesn't recover it). The SSH root path survives because the `sgowner` key is authorized through the appliance's own supported clish mechanism, so it's part of the appliance's managed config. It's also **less** drift than an unmanaged agent — it's the documented procedure.

**No inbound SSH from the outside world:** appliances have no public IP and port 22 is scoped to the VPC CIDR. The provisioner is a VPC-resident Lambda that reaches the appliances only from inside the VPC. For a human, interactive access is SSH to the private IP (or the **EC2 Serial Console** out-of-band if SSH is down); workers use SSM Session Manager.

### Deployment gates

The scanner stack doesn't report `CREATE_COMPLETE` the moment its resources exist. Two custom-resource gates hold it open until the fleet is genuinely scan-ready, so completion is a signal you can trust:

- **`WaitForRegistration`** — blocks until every appliance is registered with Vision One (automated).
- **`WaitForFileSecurity`** — then blocks until File Security is installed (the one manual console step) and each appliance is provisioned. Its `CREATE_IN_PROGRESS` state is your cue to install File Security.

## Prerequisites

1. **TrendAI Vision One account** with File Security enabled.
2. **Vision One API key** with the *"Run file scan via SDK"* permission.
3. **Service Gateway registration token** (Vision One → Workflow and Automation → Service Gateway Management → Download Virtual Appliance). **Tokens expire after 24 hours** — generate it right before deploying.
4. **AWS Marketplace subscription** to the TrendAI Service Gateway BYOL AMI (one-time, free).
5. **An S3 staging bucket** for the templates, or use the console's "Upload a template file" (the templates exceed CloudFormation's 51,200-byte inline limit).

## Deployment

```bash
# 1. Scanner infrastructure (VPC, Service Gateways, provisioner)
aws s3 cp scanner.yaml s3://<staging-bucket>/scanner.yaml
aws cloudformation create-stack \
  --stack-name scanner-1 \
  --template-url https://s3.amazonaws.com/<staging-bucket>/scanner.yaml \
  --parameters \
    ParameterKey=ServiceGatewayCount,ParameterValue=2 \
    ParameterKey=VisionOneApiKey,ParameterValue=<api-key> \
    ParameterKey=SGRegistrationToken,ParameterValue=<token> \
  --capabilities CAPABILITY_IAM \
  --disable-rollback

# 2. The stack registers the appliances automatically, then pauses at
#    WaitForFileSecurity. Install File Security on each appliance in the
#    Vision One console (Service Gateway Management → Manage Services);
#    the stack completes on its own once they're Healthy and provisioned.

# 3. Worker application (scan bucket, SQS, worker fleet)
aws s3 cp worker.yaml s3://<staging-bucket>/worker.yaml
aws cloudformation create-stack \
  --stack-name worker-1 \
  --template-url https://s3.amazonaws.com/<staging-bucket>/worker.yaml \
  --parameters ParameterKey=ScannerStackName,ParameterValue=scanner-1 \
  --capabilities CAPABILITY_IAM \
  --disable-rollback
```

Or upload `scanner.yaml` directly in the CloudFormation console (**Create stack → Upload a template file**) — no staging bucket needed. The full click-by-click flow, including the File Security install, is in the [POC Guide](POC-GUIDE.md#4-deploy-the-scanner-stack).

Then drop files into the scan bucket and watch verdicts arrive as S3 object tags and CloudWatch audit-log entries.

> **Always use a fresh, incrementing stack name** (`scanner-2`, `scanner-3`, …) and a fresh registration token; delete any retained `appliance-v1fs/*` secrets from a previous stack first, or a new stack fails with *AlreadyExists*.

## Connect your own application

Deploy only the scanner stack and skip `worker.yaml`. Your application connects to an appliance's private IP on port 443 with the File Security SDK (Java, Python, Go, or Node.js). Discover appliances the way the workers do: running EC2 instances tagged `appliance-v1fs:stack=<scanner-stack>`. Java example:

```java
AMaasClient client = new AMaasClient("", "10.2.3.45:443", apiKey, 300, true, null);
String verdict = client.scanFile("/path/to/file");   // JSON; scanResult 0 = clean
```

`scanResult 0` with a non-empty `foundErrors` means a decompression limit was hit — treat it as *not fully scanned*, not clean. Full Java walkthrough (connection reuse, TLS, response handling) is in [§10 of the POC guide](POC-GUIDE.md#10-scan-from-your-own-code-java).

### TLS and certificates

The appliance serves a self-signed wildcard cert (`*.sgi.xdr.trendmicro.com`). Workers connect by IP and satisfy hostname verification with a gRPC SNI/authority override, trusting the CA cert the watchdog extracts to Secrets Manager — so **no trendmicro.com DNS records are created in your account**. The Java SDK also offers `TM_AM_DISABLE_CERT_VERIFY=1` for by-IP connections (Java only; the Python SDK has no equivalent).

## Scaling

Fixed appliances, scaled horizontally by `ServiceGatewayCount` (1–8). Bigger instances don't help — each appliance runs one scanner pod with a fixed 32-handler concurrency (nginx HTTP/2 pins connections to one pod, so extra replicas sit idle). Scale out, not up.

Benchmarked on this architecture (real-world malware, scan cache disabled — worst case):

| Appliances (c5.2xlarge) | Sustained | Files/day |
|---|---|---|
| 1 | ~170/s | 14.7M |
| 2 | ~339/s | 29.3M |
| 4 | ~679/s | 58.7M |
| 8 | ~1,358/s | 117.3M |

Production workloads with the Redis scan cache enabled (the appliance default) see significantly higher throughput on repeated file hashes.

**Scaling up** is a stack update to a higher count — the gates re-run and pause at `WaitForFileSecurity` so you install File Security on the new appliances. **Scaling down** requires disabling termination protection on the surplus appliances first (they're protected by design). See [§15 of the POC guide](POC-GUIDE.md#15-day-to-day-operation).

## Security

- **IMDSv2 required**, **EBS encrypted**, **S3 AES256 + HTTPS-only + public-access-blocked**, **SQS SSE**, **SNS KMS**, **VPC Flow Logs**, **X-Ray** on Lambdas.
- **All AWS API traffic stays in the VPC** via an S3 gateway endpoint and interface endpoints; the appliances' only internet-bound traffic is outbound 443 to Vision One.
- **No inbound SSH from the outside world** — appliances have no public IP; port 22 is VPC-CIDR scoped; provisioning is VPC-internal.
- **Termination protection** on appliances; **secrets** in Secrets Manager (`NoEcho` parameters); **least-privilege IAM** throughout.

## Project structure

```
scanner.yaml            CloudFormation: VPC, Service Gateways, provisioner, gates, secrets
worker.yaml             CloudFormation: scan/quarantine buckets, SQS, worker fleet, dashboard
buildspec-scanner.yml   CodeBuild: provisioner paramiko layer + code
buildspec-worker.yml    CodeBuild: worker app package
app/
  scanner.py            Async SQS→S3→gRPC scan→route worker
  requirements.txt      visionone-filesecurity, aiobotocore, boto3
lambda/provisioner/
  handler.py            Watchdog + deploy gates (SSH: admin clish + sgowner root)
  ssh_helper.py         paramiko ClishSession (interactive clish over SSH)
POC-GUIDE.md            Full end-to-end evaluation guide
assets/architecture.svg Architecture diagram (embedded in the guide)
```

## Cleanup

```bash
# Empty the buckets first (CloudFormation won't delete non-empty buckets)
# then delete the worker stack, disable termination protection on the
# appliances, delete the scanner stack, disconnect the appliances in the
# Vision One console, and delete the retained appliance-v1fs/* secrets.
aws cloudformation delete-stack --stack-name worker-1
```

The full ordered teardown (including the two steps people miss — termination protection and retained secrets) is in [§17 of the POC guide](POC-GUIDE.md#17-teardown).
