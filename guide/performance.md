# Performance and Scaling

## Architecture Summary

EC2 worker fleet polling SQS, scanning via gRPC to Service Gateway virtual appliances. S3 replication copies files from the source bucket to a scan bucket; EventBridge routes object-created events to SQS. Workers download files, scan via gRPC, tag/quarantine results, and delete the scan copy.

## Autoscaling Configuration

### Worker Fleet (ASG)
- Instance type: t3.medium (2 vCPU, 4 GB)
- Range: 2 (min, HA across AZs) to 10 (max)
- Scaling trigger: SQS `ApproximateNumberOfMessagesVisible`
- Step scaling thresholds: +2 at 100, +3 at 1,000, +5 at 5,000 messages
- Scale-in: -1 when queue < 10 messages
- Estimated instance warmup: 120s (scale-out), 300s (scale-in)
- Lifecycle hook: `WorkerTerminationHook` with 330s heartbeat for graceful shutdown
- Workers complete in-flight scans before terminating via `CompleteLifecycleAction`

### Service Gateway Fleet
- 3x c5.4xlarge (always running, no autoscaling)
- 2 gRPC channels per SG = 6 total channels
- Provisioned automatically via EventBridge → Lambda on EC2 state change
- Provisioner waits for FSVA scanner pod to be Running before marking provisioned

## Worker Settings
- `MAX_CONCURRENT_SCANS`: 50 per worker
- At max scale: 10 workers x 50 concurrent = 500 scan slots
- SQS long-polling: 20s `ReceiveMessageWaitTimeSeconds`
- Visibility timeout: 300s with heartbeat extension for long-running scans
- S3 Gateway VPC endpoint eliminates NAT data processing for S3 traffic

## Stress Test Results (stack-18, 2026-04-02)

Tested with 207,898 real malware samples (64 batches of 3,258 files, mixed sizes) copied at 231 files/sec (20M files/day equivalent) for 15 minutes via S3 server-side copy.

### Throughput

| Metric | Value |
|---|---|
| Files ingested | 207,898 |
| Ingest rate | 229 files/sec (sustained) |
| Files scanned | 207,898 (100%, 0 lost) |
| Scan errors | **0** |
| DLQ messages | **0** |
| Detection rate | 83.4% malicious, 16.6% clean |
| SG load balance | 34.9% / 33.1% / 32.0% across 3 SGs |

### Per-Worker Throughput

| Worker | Processed | Malicious | Clean | Errors | Time Active |
|---|---|---|---|---|---|
| i-0826acc1a40bef78a | 37,097 | 30,997 | 6,116 | 0 | Full test (original) |
| i-0c5ad078c203bddb9 | 37,385 | 31,170 | 6,239 | 0 | Full test (original) |
| i-026190d05e21d2a09 | 21,295 | 17,731 | 3,574 | 0 | ~10 min (scale-up) |
| i-0f025347aa7487e00 | 20,627 | 17,212 | 3,423 | 0 | ~10 min (scale-up) |
| i-0f2681bb1a8896c90 | 20,267 | 16,872 | 3,411 | 0 | ~10 min (scale-up) |
| i-05280fa639c9cb4ef | 20,192 | 16,912 | 3,300 | 0 | ~10 min (scale-up) |
| i-02e186f447e5089a0 | 13,148 | 11,001 | 2,157 | 0 | ~7 min (scale-up) |
| i-09f8a28b2bcf56b4e | 13,163 | 10,993 | 2,174 | 0 | ~7 min (scale-up) |
| i-0824cff7801814ff3 | 12,321 | 10,263 | 2,070 | 0 | ~7 min (scale-up) |
| i-0518ef19525ea4249 | 12,403 | 10,335 | 2,076 | 0 | ~7 min (scale-up) |
| **Total (10 workers)** | **207,898** | **173,486** | **34,540** | **0** | |

**Effective rate per worker: ~36 files/sec** (original workers with full test duration)

### ASG Scaling Timeline

| Time | Event |
|---|---|
| T+0:00 | Test begins, 2 workers InService |
| T+5:30 | ASG scales to 6 (4 new workers launched) |
| T+8:30 | ASG scales to 10 (max, 4 more workers launched) |
| T+10:00 | Queue starts shrinking (scan rate > ingest rate) |
| T+15:00 | Ingest stops, queue draining |
| T+~18:00 | Queue fully drained to 0 |

### Scan Latency

| Percentile | All Files | Clean | Malicious |
|---|---|---|---|
| p50 | 112ms | 110ms | 113ms |
| p90 | 249ms | 250ms | 249ms |
| p95 | 308ms | 318ms | 304ms |
| p99 | 432ms | 460ms | 430ms |
| max | 1,174ms | 768ms | 1,174ms |
| avg | 136ms | 136ms | 136ms |

### File Size Distribution

| Percentile | All Files | Clean | Malicious |
|---|---|---|---|
| p50 | 156 KB | 68 KB | 172 KB |
| p90 | 1.1 MB | 1.0 MB | 1.1 MB |
| p95 | 2.3 MB | 3.0 MB | 2.2 MB |
| p99 | 6.1 MB | 5.8 MB | 6.2 MB |
| max | 40.0 MB | 22.3 MB | 40.0 MB |
| avg | 537 KB | 516 KB | 542 KB |

### Pipeline Verification

| Check | Result |
|---|---|
| S3 replication (source → scan) | Working |
| EventBridge → SQS routing | Working |
| gRPC scan via Service Gateway | Working |
| Source bucket malware tagging | Working (`ScanResult=Malware`) |
| Bucket policy malware access deny | Working |
| Quarantine copy | Working (173,486 objects) |
| Scan bucket cleanup (delete after scan) | Working (0 remaining) |
| DLQ | **0 messages** |
| Audit log | All scans logged |

## Performance Characteristics

- **Scanner is I/O bound, not CPU bound** — worker CPU stays low, bottleneck is gRPC scan engine analysis time
- **Scan latency is driven by file complexity, not size** — malware analysis involves decompression, heuristics, and pattern matching
- **gRPC scan cache exists** — repeated scans of identical file hashes return cached results (artificially fast on same-stack reruns)
- **S3 Gateway VPC endpoint** eliminates NAT data processing charges for all S3 traffic (the dominant data path)
- **Worker concurrency (50)** is the per-instance throttle — increasing beyond 50 risks gRPC channel saturation

## Scaling

| Workers | Scan Rate | Daily Capacity |
|---|---|---|
| 2 (min) | ~72/s | 6.2M/day |
| 4 | ~144/s | 12.4M/day |
| 7 | ~252/s | 21.8M/day |
| 10 (max) | ~360/s | 31.1M/day |

**Each additional t3.medium worker adds ~36 files/sec (~3.1M files/day)**. To increase beyond 10 workers, raise the `WorkerMaxCount` parameter. The SG fleet (3x c5.4xlarge with 2 channels each) can support well beyond 10 workers — the bottleneck is worker count, not SG capacity.

## Instance Sizing

### Service Gateways — c5.4xlarge (16 vCPU, 32 GB)

The c5.4xlarge is overprovisioned. At peak load, the scanner pod uses ~26m CPU and ~1.7 GB memory. **c5.2xlarge handles the same throughput at half the cost** and meets the TrendAI minimum spec (8 CPUs, 12 GB memory). Going smaller is not supported — c5.xlarge (4 vCPU, 8 GB) is below the TrendAI minimum.

### Workers — t3.medium (2 vCPU, 4 GB)

Workers are lightweight Python processes polling SQS and forwarding to gRPC. CPU and memory usage is minimal. t3.medium provides sufficient headroom for 50 concurrent scans with file buffering.

## Cost Analysis

### 2M files/day (23 files/sec)

| Component | Monthly Cost | Notes |
|---|---|---|
| EC2 — Service Gateways | $1,489.20 | 3x c5.4xlarge (or $744.60 with c5.2xlarge) |
| EC2 — Workers | $60.74 | 2x t3.medium (min fleet) |
| NAT Gateway | $67.05 | 2 AZs, non-S3 traffic only |
| S3 — Operations | $1,172.40 | PUT/GET/DELETE across source, scan, quarantine |
| S3 — Storage | $1,296.38 | Source + quarantine accumulation (537 KB avg) |
| SQS | $79.20 | ~198M requests/month |
| EventBridge | $60.00 | 60M events/month |
| CloudWatch Logs | $14.81 | Audit trail (~500 bytes/event) |
| Secrets Manager | $1.30 | 2 secrets, minimal API calls (cached) |
| **TOTAL** | **$4,241.08/mo** | |
| Per file | $0.000071 | |
| Per 1M files | $70.68 | |

### 20M files/day (231 files/sec)

| Component | Monthly Cost | Notes |
|---|---|---|
| EC2 — Service Gateways | $1,489.20 | 3x c5.4xlarge (or $744.60 with c5.2xlarge) |
| EC2 — Workers | $212.58 | 7x t3.medium |
| NAT Gateway | $67.05 | 2 AZs, non-S3 traffic only |
| S3 — Operations | $11,724.00 | PUT/GET/DELETE across source, scan, quarantine |
| S3 — Storage | $12,963.84 | Source + quarantine accumulation (537 KB avg) |
| SQS | $792.00 | ~1.98B requests/month |
| EventBridge | $600.00 | 600M events/month |
| CloudWatch Logs | $148.08 | Audit trail (~500 bytes/event) |
| Secrets Manager | $1.30 | 2 secrets, minimal API calls (cached) |
| **TOTAL** | **$27,998.05/mo** | |
| Per file | $0.000047 | |
| Per 1M files | $46.66 | |

### Cost Optimization Notes

- **Switch SGs to c5.2xlarge**: saves $744.60/mo (identical throughput, half the instance cost)
- **S3 storage dominates at scale**: consider lifecycle policies to expire or transition quarantine/source objects
- **S3 operations are the largest variable cost**: driven by replication + scan + quarantine writes per file
- **Workers are negligible**: even at max scale (10x t3.medium), only $304/mo
- **S3 Gateway VPC endpoint**: already eliminates NAT data processing for S3 traffic (~$0.045/GB savings)

## Observability

- **SSM Session Manager**: all EC2 instances (workers + SGs) accessible via SSM
- **CloudWatch Audit Log**: `scan-audit-${StackName}`, structured JSON per scan event
- **CloudWatch Dashboard**: `scanner-${StackName}` with queue health, throughput, and scaling metrics
- **CloudWatch Alarms**: DLQ messages (> 0), queue age (> 20 min), queue depth (> 10,000)
- **DLQ Remediation Lambda**: auto re-queues with backoff (60s/300s/900s), max 5 retries
- **Worker logs**: `journalctl -u scanner` via SSM (no CloudWatch agent yet)

## Comparison: EC2 Workers vs Lambda (Previous Architecture)

| Metric | Lambda (stack-17) | EC2 Workers (stack-18) |
|---|---|---|
| Compute cost (20M/day) | ~$15,000/mo | ~$1,702/mo (EC2 only) |
| Scan latency p50 | ~160ms | 112ms |
| Max concurrency | 1,000 (account limit) | 500 (10 workers x 50) |
| Scaling speed | Instant | ~3 min (ASG + bootstrap) |
| Cold start | Yes (Lambda init) | No (always polling) |
| Per-file overhead | High (invoke + init) | Low (amortized polling) |
| SSM access | N/A | All instances |
| Graceful shutdown | N/A | Lifecycle hook + SIGTERM |
