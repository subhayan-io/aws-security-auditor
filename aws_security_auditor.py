#!/usr/bin/env python3
"""
AWS Cloud Security Auditor
Audits AWS environments for common security misconfigurations:
1. Publicly accessible S3 buckets (Public Access Block status)
2. Stale IAM access keys (> 90 days old)
3. EC2 instances exposing IMDSv1 (HttpTokens != 'required')
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone


def audit_s3_public_access(s3_client):
    print("\n--- [1] Auditing S3 Public Access Blocks ---")
    findings = []
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
        if not buckets:
            print("No S3 buckets found.")
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all(config.values()):
                    findings.append(name)
                    print(f"[HIGH] Bucket '{name}' does NOT block all public access: {config}")
                else:
                    print(f"[OK]   Bucket '{name}' has full Public Access Block enabled.")
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(name)
                    print(f"[HIGH] Bucket '{name}' has NO Public Access Block configured!")
                else:
                    print(f"[ERR]  Could not inspect bucket '{name}': {e}")
    except ClientError as e:
        print(f"[ERR]  Failed to list S3 buckets: {e}")
    return findings


def audit_stale_iam_keys(iam_client, max_age_days=90):
    print(f"\n--- [2] Auditing IAM Access Keys (> {max_age_days} days) ---")
    findings = []
    now = datetime.now(timezone.utc)
    try:
        users = iam_client.list_users().get("Users", [])
        if not users:
            print("No IAM users found.")
            return findings

        for user in users:
            username = user["UserName"]
            keys = iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key["Status"] == "Active":
                    age = (now - key["CreateDate"]).days
                    key_id = key["AccessKeyId"]
                    if age > max_age_days:
                        findings.append((username, key_id, age))
                        print(f"[MED]  User '{username}' has active key {key_id} aged {age} days.")
                    else:
                        print(f"[OK]   User '{username}' key {key_id} is {age} days old.")
    except ClientError as e:
        print(f"[ERR]  Failed to audit IAM keys: {e}")
    return findings


def audit_ec2_imdsv2(ec2_client):
    print("\n--- [3] Auditing EC2 Instance Metadata Service (IMDSv2 Enforcement) ---")
    findings = []
    try:
        reservations = ec2_client.describe_instances().get("Reservations", [])
        instances = [inst for res in reservations for inst in res.get("Instances", [])]
        if not instances:
            print("No EC2 instances found in current region.")
            return findings

        for inst in instances:
            inst_id = inst["InstanceId"]
            state = inst["State"]["Name"]
            if state == "terminated":
                continue
            http_tokens = inst.get("MetadataOptions", {}).get("HttpTokens", "optional")
            if http_tokens != "required":
                findings.append((inst_id, http_tokens))
                print(f"[HIGH] Instance '{inst_id}' ({state}) allows IMDSv1 (HttpTokens={http_tokens}).")
            else:
                print(f"[OK]   Instance '{inst_id}' ({state}) enforces IMDSv2.")
    except ClientError as e:
        print(f"[ERR]  Failed to describe EC2 instances: {e}")
    return findings


def main():
    print("=== AWS Cloud Security Posture Audit ===")
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        print(f"Account ID: {identity['Account']} | ARN: {identity['Arn']}")

        s3 = boto3.client("s3")
        iam = boto3.client("iam")
        ec2 = boto3.client("ec2")

        s3_issues = audit_s3_public_access(s3)
        iam_issues = audit_stale_iam_keys(iam)
        ec2_issues = audit_ec2_imdsv2(ec2)

        print("\n=== Audit Summary ===")
        print(f"S3 Public Access Risks : {len(s3_issues)}")
        print(f"Stale IAM Access Keys  : {len(iam_issues)}")
        print(f"EC2 IMDSv1 Exposures   : {len(ec2_issues)}")

    except NoCredentialsError:
        print("[ERROR] No AWS credentials found. Run 'aws configure' or export AWS environment variables.")
    except ClientError as e:
        print(f"[ERROR] AWS API error: {e}")


if __name__ == "__main__":
    main()