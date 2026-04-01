# Operations Guide

## Deployment Flow

1. **Create deploy bucket:** `aws s3 mb s3://{deploy-bucket}` (teardown deletes it; recreate before each deploy)
2. **Upload template:** `aws s3 cp appliance-v1fs.yaml s3://{deploy-bucket}/template.yaml`
3. **Deploy stack:**
   ```bash
   aws cloudformation create-stack \
     --stack-name appliance-v1fs-N \
     --template-url https://s3.amazonaws.com/{deploy-bucket}/template.yaml \
     --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
     --disable-rollback
   ```
4. Stack creates all infrastructure; CodeBuild pulls from GitHub, builds Lambda layers and code zips
5. EC2 instances launch → EventBridge fires → provisioner Lambda registers each SG
6. **Manual step:** Install File Security on all SGs via Vision One console (Workflow and Automation → Service Gateway Management → Manage Services)
7. Scanning begins automatically

### Stack Naming

Always use incrementing stack names: `appliance-v1fs-1`, `appliance-v1fs-2`, etc. Never reuse.

### Template Size

The template exceeds 51,200 bytes — must deploy via S3 URL, not `--template-body`.

**Do not upload templates to the ingest bucket** — EventBridge will route them to the scanner.

### Post-Deploy Code Updates

CodeBuild runs once at stack creation. Code changes pushed to GitHub after stack creation require:
```bash
aws codebuild start-build --project-name {codebuild-project}
aws lambda update-function-code --function-name scanner-{stack} --s3-bucket {deploy-bucket} --s3-key scanner-code.zip
```

## Provisioner Lambda

- **Non-VPC:** Runs outside the VPC, connects to SGs via EICE SSH tunnels
- **AWS CLI v2:** Downloaded from S3 to `/tmp` at cold start (not bundled in layer)
- **Provisioning:** Triggered by EventBridge EC2 state-change events when instances reach `running`
- **Root access:** Uses sgowner via KB article KA-0014380 (generate RSA key, install via `configure verify cli support`, SSH as sgowner)
- **Cert extraction:** Via sgowner `openssl s_client` to localhost:443 — works before FS install (cert is from the AMI's nginx)
- **Hostname:** Sets OS hostname via `hostnamectl set-hostname` through sgowner SSH (Vision One uses OS hostname, not clish endpoint name)
- **Watchdog:** Runs every 15 minutes, checks scanner versions, re-extracts cert and re-applies nginx patch if version changes

### nginx Body Size Patch

The default nginx configmap has `proxy-body-size: 10m`, blocking gRPC scans >10MB. The provisioner patches this to match `MaxFileSizeMB` (default 500MB) during initial provisioning. The watchdog re-applies it every 15 minutes in case a scanner pod update reverts the configmap.

## SSH & CLI Gotchas

- **clish space handling:** Use `paramiko.invoke_shell()` with character-by-character sends (10ms delay). Never use `exec_command()` for clish.
- **clish has no shell escape** — `execute shell` doesn't work. For shell access, use sgowner root path.
- **Root access:** Per KB KA-0014380: generate RSA 4096 key, `configure verify cli support {base64_pubkey}` via admin clish, SSH as `sgowner`, `sudo su -` for root.
- **MicroK8s Calico CNI doesn't support hostPort or NodePort binding** — no kube-proxy running.
- **Admin readiness:** Retries every 15s until admin commands accepted.
- **`configure verify plat`** shows pod status. Look for `sg-sfs-scanner` with `Running`.
- **SSM Agent not supported** — use EICE for SSH.
- **Same self-signed cert on all SG AMI instances** — CN `*.sgi.xdr.trendmicro.com`.
- **Vision One uses OS hostname** — set via `hostnamectl set-hostname` through sgowner SSH, not `configure endpoint` via clish.

## BuildSpec (CodeBuild)

CodeBuild pulls from GitHub and:
1. Builds scanner Lambda layer (visionone-filesecurity + gRPC) → uploads to S3 deploy bucket
2. Zips scanner.py → uploads to S3 deploy bucket
3. Builds provisioner Lambda layer (paramiko only) → uploads to S3 deploy bucket
4. Downloads AWS CLI v2, zips the `dist/` directory → uploads `awscli-runtime.zip` to S3 deploy bucket
5. Zips provisioner code → uploads to S3 deploy bucket
6. Uploads `enrollment.yaml` to S3 deploy bucket

### AWS CLI v2 in Lambda

The AWS CLI v2 binary **cannot be bundled in a Lambda layer** due to:
- Lambda doesn't preserve symlinks from layer zips
- PyInstaller botocore data can't be stripped (internal index breaks)
- Unstripped, it exceeds the 250MB layer limit

**Solution:** CodeBuild uploads the AWS CLI `dist/` directory as `awscli-runtime.zip` to S3. The provisioner downloads and extracts it to `/tmp` on cold start.

**YAML gotcha:** The `--only-binary=:all:` pip flag contains colons that YAML interprets as tags. The command must be quoted.

## Undocumented ICAP Interface

The scanner pod exposes an ICAP service on port 1344 (documented only for the containerized scanner, not the virtual appliance). **Not used in production** — ICAP has size limitations and requires iptables DNAT workarounds that don't persist across reboots.
