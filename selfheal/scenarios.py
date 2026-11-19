"""The three controlled scenarios from the Round 2 deck, plus a mixed one."""
from __future__ import annotations

import json


def seed_controlled(region: str = "us-east-1") -> dict:
    """Create a small vulnerable account: public bucket, open SSH, CloudTrail off."""
    import boto3
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    ct = boto3.client("cloudtrail", region_name=region)
    iam = boto3.client("iam", region_name=region)

    # 1. Public S3 bucket: public-read ACL, no Block Public Access
    s3.create_bucket(Bucket="customer-exports")
    s3.put_bucket_ownership_controls(Bucket="customer-exports", OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]})
    s3.put_bucket_acl(Bucket="customer-exports", ACL="public-read")
    s3.put_bucket_versioning(Bucket="customer-exports", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket="customer-exports", ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})

    # 2. Unrestricted SSH on a web server security group (HTTPS is meant to be public)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="web-server", Description="web tier", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])

    # 3. CloudTrail exists but logging is switched off
    s3.create_bucket(Bucket="audit-logs-trail")
    for k, v in (("BlockPublicAcls", True),):
        pass
    s3.put_public_access_block(Bucket="audit-logs-trail", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket="audit-logs-trail", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket="audit-logs-trail", ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    ct.create_trail(Name="org-audit", S3BucketName="audit-logs-trail", IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.stop_logging(Name="org-audit")
    return {"bucket": "customer-exports", "security_group": sg, "trail": "org-audit"}


def seed_extra(region: str = "us-east-1") -> None:
    """Extra findings for the full demo, including one HIGH-risk IAM finding."""
    import boto3
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)
    s3.create_bucket(Bucket="ml-training-data")  # private by ACL but no PAB, no versioning, no KMS
    sg = ec2.create_security_group(GroupName="legacy-windows", Description="rdp box")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    iam.create_policy(PolicyName="dev-full-access", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
