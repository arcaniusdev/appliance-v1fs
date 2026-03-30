# Full Account Teardown

Delete all billable resources in the AWS account. Leave default AWS resources (default VPC, default security groups, etc.) intact.

## Step 1: Delete CloudFormation Stacks

List all CloudFormation stacks in us-east-1 (exclude DELETE_COMPLETE). Delete each one. Do not wait for completion before proceeding — AWS handles deletion asynchronously.

## Step 2: Clean Up S3 Buckets

List all S3 buckets in the account. This includes CloudFormation-managed buckets AND auto-created `{source}-clean` and `{source}-quarantine` buckets created by the scanner at runtime. For each bucket:
1. Delete all object versions and delete markers (use `list-object-versions` and `delete-objects` in batches of 1000, handle pagination)
2. Delete the empty bucket with `aws s3 rb`

Run bucket cleanups in parallel.

**Exception:** Never delete the `eks-v1fs-malware-samples-886436954261` bucket — it contains real-world malware samples that take 50+ minutes to download.

## Step 3: Delete EBS Volumes

Find all EBS volumes in `available` state. Delete all of them.

## Step 4: Delete ECR Repositories

List all ECR repositories. For each, delete with `--force` (removes all images).

## Step 5: Delete Secrets Manager Secrets

List all Secrets Manager secrets. Delete each with `--force-delete-without-recovery`.

**Exceptions:**
- Never delete `appliance-v1fs/vision-one-api-key` — it stores the reusable TrendAI Vision One API key.
- Never delete `appliance-v1fs/sg-registration-token` — it stores the reusable Service Gateway registration token.

## Step 6: Delete CloudWatch Log Groups

List all CloudWatch log groups. Delete all of them.

## Step 7: Delete Other Billable Resources

Check for and delete each of the following if they exist:
- EC2 instances (terminate any running or stopped instances)
- Elastic IPs (release any allocated EIPs)
- NAT Gateways (delete any non-deleted NAT Gateways)
- EC2 Instance Connect Endpoints (delete any endpoints)
- Load Balancers (ALB, NLB, and Classic — delete all)
- Lambda functions (delete all)
- SQS queues (delete all)
- VPC endpoints (delete any non-default endpoints)
- SSM parameters under `/ec2/keypair/` (delete any key pair parameters)
- SSM parameters under `/appliance-v1fs/` (enrolled-buckets registry, scanner-version tracking)
- EC2 key pairs (delete all)
- CodeBuild projects (delete all)

## Step 8: Wait for Stack Deletion

If any stacks were deleted in Step 1, poll until all are fully deleted or report failures.

## Step 9: Delete Non-Default VPCs

After stacks and NAT Gateways are deleted, find all non-default VPCs. For each:
1. Delete any remaining subnets
2. Detach and delete internet gateways
3. Delete route tables (non-main)
4. Delete security groups (non-default)
5. Delete the VPC

## Step 10: Re-check for Orphaned Resources

After stacks are deleted, re-run checks for EBS volumes, Elastic IPs, ENIs, and security groups that may have been released by stack deletion. Delete any newly orphaned billable resources.

## Step 11: Final Verification

Run a comprehensive scan of all resource types checked above. Report a summary table of what was deleted and confirm the account is clean, or list anything that remains.

## Important Notes

- All operations are in us-east-1
- This deletes EVERYTHING billable, not just appliance-v1fs resources
- Leave default VPC, default subnets, default security groups, default route tables, default NACLs, and default internet gateway — these are free and come with the account
- Never delete the `eks-v1fs-malware-samples-886436954261` bucket
- Never delete the `appliance-v1fs/vision-one-api-key` secret
- Never delete the `appliance-v1fs/sg-registration-token` secret
- Do not delete IAM users, roles, or policies (free tier, and deleting them could lock out access)
