# AWS Cloud Security Auditor

A lightweight Python CLI tool built with `boto3` to audit AWS accounts for high-impact cloud security misconfigurations.

## Checks Performed
1. **S3 Public Access Blocks:** Flags buckets missing full `PublicAccessBlockConfiguration` enforcement.
2. **Stale IAM Access Keys:** Identifies active IAM user access keys older than 90 days.
3. **EC2 IMDSv2 Enforcement:** Detects running or stopped EC2 instances where `HttpTokens` is not set to `required` (preventing SSRF metadata credential theft).

## Prerequisites
* Python 3.9+
* Configured AWS credentials (`aws configure` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables) with read-only IAM permissions (`s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `iam:ListUsers`, `iam:ListAccessKeys`, `ec2:DescribeInstances`, `sts:GetCallerIdentity`).

## Installation & Usage
```bash
pip install -r requirements.txt
python aws_security_auditor.py 