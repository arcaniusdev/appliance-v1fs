# Performance Guide

## Instance Sizing

### c5.2xlarge (8 vCPU, 16 GB) — Optimal

The c5.4xlarge is massively overprovisioned. At peak load, the scanner pod uses ~26m CPU and ~1.7GB memory. **c5.2xlarge handles the same throughput at half the cost** and meets the TrendAI minimum spec (8 CPUs, 12 GB memory).

Going smaller is not supported — c5.xlarge (4 vCPU, 8 GB) is below the TrendAI minimum spec. Memory-optimized instances (r-series) provide no benefit since the scanner pod uses minimal memory.

## Stress Test Results (2 SGs, c5.2xlarge, 2 channels each)

Tested with 163K real malware samples (50 batches of 3,258 files, mixed sizes up to 395MB).

| Metric | Value |
|---|---|
| Peak throughput | ~253 files/sec (15,179 invocations/min) |
| Steady-state throughput | ~170 files/sec (~14.7M files/day) |
| Peak Lambda concurrency | 999 (hit account limit of 1,000) |
| Errors | **0** |
| DLQ messages | **0** |
| Detection rate | 46.8% malicious, 53.2% clean |
| Load balance | 49.8% / 50.2% across 2 SGs |

## Scan Latency

| Percentile | Latency |
|---|---|
| P50 | ~160ms |
| P95 | ~5.2s |
| P99 | ~40s |
| Max | ~90s (large files) |
| Min | 2-3ms (cached/small) |

## Large File Scanning (nginx patched)

| File Size | Scan Time | Result |
|---|---|---|
| 395MB | 2.1s | Clean |
| 58MB | 9.9s | Malicious |
| 47MB | 7.6s | Malicious |
| 46MB | 18.5s | Malicious |
| 33MB | 10.6s | Malicious |

## Key Performance Facts

- Scanner pod doesn't autoscale (no HPA on virtual appliance, single replica)
- **Lambda concurrency is the primary bottleneck** — request increases via Service Quotas as needed
- `TM_AM_MAX_HANDLER: 32` concurrent scan handlers per scanner pod
- Scanner pod has 4 containers: scanner, uploader, connector, redis
- gRPC scan cache exists (`TM_AM_SCAN_CACHE=true`)
- 2 SGs handle ~14.7M files/day; 3 SGs estimated ~20M/day (with sufficient Lambda concurrency)

## Scaling

The only way to increase throughput is **adding more SGs** (horizontal scaling). Bigger instances don't help because the scanner pod has a fixed 32-handler limit and uses minimal resources. Each additional c5.2xlarge SG adds another ~7.3M files/day capacity.

## Cost Estimates

| Scenario | SGs | Monthly Cost |
|---|---|---|
| Baseline (~2M files/day) | 2x c5.2xlarge | ~$500 |
| Production (~14M files/day) | 2x c5.2xlarge | ~$500 |
| High volume (~20M files/day) | 3x c5.2xlarge | ~$750 |

*Costs are for EC2 only. Lambda, SQS, S3, and data transfer are additional.*
