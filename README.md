# TrendAI Service Gateway File Scanner on AWS

CloudFormation-deployed S3 malware scanning built on the TrendAI Vision One File Security Virtual Appliance. Files arriving in an S3 bucket trigger SQS notifications to an EC2 worker fleet that scans them through Service Gateway appliances using the official File Security SDK over gRPC/TLS.

```
Scan Bucket → S3 Notification → SQS → EC2 Worker Fleet → gRPC/TLS :443 → Service Gateways
  ├── Clean:     tag ScanResult=Clean, leave in scan bucket
  └── Malicious: tag ScanResult=Malware, copy to quarantine, delete from scan bucket
```

## Highlights

- **Stock appliance** — the Service Gateway runs the unmodified TrendAI Marketplace AMI; scanning uses the documented SDK endpoint (gRPC over TLS, port 443) with the SDK's built-in certificate-trust (`ca_cert`) mechanism
- **Hands-free provisioning** — a watchdog Lambda registers appliances with Vision One, extracts the TLS certificate, and applies hardening via SSM RunCommand (no SSH, no key pairs)
- **Horizontally scalable** — 1–8 fixed appliance instances; workers discover them by EC2 tag and balance load across all of them
- **Private by default** — VPC endpoints keep all AWS API traffic internal; appliances need only outbound 443 to Vision One
- **Benchmarked** — 339 scans/s sustained (29M files/day) on 2× c5.2xlarge with real-world malware samples and the scan cache disabled; scales linearly per appliance

## Prerequisites

1. TrendAI Vision One account with File Security enabled
2. Vision One API key (for the File Security SDK)
3. Service Gateway registration token (Vision One console → Workflow and Automation → Service Gateway Management; tokens expire after 24 hours)
4. AWS Marketplace subscription to the TrendAI Service Gateway BYOL AMI
5. An S3 staging bucket for the templates (they exceed the 51,200-byte inline limit)

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

# 2. Wait for the watchdog to register the appliances (check for the
#    appliance-v1fs:registered=true EC2 tag), then install File Security on
#    each appliance in the Vision One console (Service Gateway Management →
#    Manage Services). The watchdog completes provisioning on its next run.

# 3. Worker application (scan bucket, SQS, worker fleet)
aws s3 cp worker.yaml s3://<staging-bucket>/worker.yaml
aws cloudformation create-stack \
  --stack-name worker-1 \
  --template-url https://s3.amazonaws.com/<staging-bucket>/worker.yaml \
  --parameters ParameterKey=ScannerStackName,ParameterValue=scanner-1 \
  --capabilities CAPABILITY_IAM \
  --disable-rollback
```

Drop files into the scan bucket and watch verdicts arrive as S3 object tags and CloudWatch audit-log entries. The two stacks are independent: the scanner stack exports its VPC and discovery tags, so any application can integrate the scanning fleet the same way the demo worker does.

## Operational notes

- **Stack names**: use a fresh, incrementing stack name for each deployment; generate a fresh registration token each time (tokens expire after 24 hours)
- **Appliance access**: all automation uses SSM RunCommand; interactive access is SSM Session Manager (`aws ssm start-session --target <instance-id>`). No SSH key pairs are created or required.
- **TLS**: workers connect to the documented appliance scanner endpoint (gRPC over TLS, port 443). The provisioner extracts the appliance certificate to Secrets Manager automatically and disables weak TLS ciphers using the appliance's documented CLI command.
- **Scan policy**: decompression limits (nesting depth, ratio, file count, size) are configurable in the Vision One console under File Security → Virtual Appliance
- **Instance types**: c5.2xlarge is the documented default. TrendAI documents support for the C5, C6, and C7 series; verify Marketplace AMI eligibility before selecting c6i/c7i types.
- All template parameters are documented inline in `scanner.yaml` and `worker.yaml`

## Sizing

| Appliances (c5.2xlarge) | Capacity (cache disabled) | Files/Day |
|---|---|---|
| 1 | ~170/s | 14.7M |
| 2 | ~339/s | 29.3M |
| 4 | ~679/s | 58.7M |
| 8 | ~1,358/s | 117.3M |

Production workloads with the Redis scan cache enabled (the appliance default) see significantly higher throughput on repeated file hashes.
