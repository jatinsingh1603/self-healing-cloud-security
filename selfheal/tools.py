"""Approved remediation tools.

The AI (or rule) selector may only pick a tool from this registry. Each tool
declares (a) which rule it is allowed to fix, (b) the exact IAM actions it
needs, which together form the least-privilege remediator policy, and
(c) a risk tier. HIGH risk tools are never run without human approval.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from botocore.exceptions import ClientError

from .checks import WORLD, _all_ports, _covers, get_security_group
from .model import Finding, Rule


@dataclass(frozen=True)
class Tool:
    name: str
    fixes: Rule
    actions: tuple[str, ...]
    risk: str               # LOW | MEDIUM | HIGH
    description: str
    run: Callable


# ------------------------------------------------------------------ S3
def _fix_s3_public_access(sess, f: Finding) -> str:
    s3 = sess.client("s3")
    s3.put_public_access_block(Bucket=f.resource_id, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    msg = "public access block enabled (all 4 settings)"
    if f.evidence.get("acl_public"):
        s3.put_bucket_acl(Bucket=f.resource_id, ACL="private")
        msg += "; ACL reset to private"
    return msg


def _enable_s3_versioning(sess, f: Finding) -> str:
    sess.client("s3").put_bucket_versioning(Bucket=f.resource_id, VersioningConfiguration={"Status": "Enabled"})
    return "versioning enabled"


def _enable_s3_kms(sess, f: Finding) -> str:
    sess.client("s3").put_bucket_encryption(Bucket=f.resource_id, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]})
    return "default SSE-KMS encryption enabled (aws/s3 key)"


# ------------------------------------------------------------------ Security groups
def _revoke_world(sess, f: Finding, test) -> str:
    ec2 = sess.client("ec2")
    sg = get_security_group(ec2, f.resource_id)
    if not sg:
        return "security group no longer exists"
    admin_cidr = os.environ.get("SELFHEAL_ADMIN_CIDR")  # optional: re-grant to a trusted range
    revoked = 0
    for p in sg.get("IpPermissions", []):
        if not test(p):
            continue
        v4 = [r for r in p.get("IpRanges", []) if r.get("CidrIp") in WORLD]
        v6 = [r for r in p.get("Ipv6Ranges", []) if r.get("CidrIpv6") in WORLD]
        if not (v4 or v6):
            continue
        perm = {k: p[k] for k in ("IpProtocol", "FromPort", "ToPort") if k in p}
        if v4:
            perm["IpRanges"] = [{"CidrIp": r["CidrIp"]} for r in v4]
        if v6:
            perm["Ipv6Ranges"] = [{"CidrIpv6": r["CidrIpv6"]} for r in v6]
        ec2.revoke_security_group_ingress(GroupId=f.resource_id, IpPermissions=[perm])
        revoked += 1
        if admin_cidr:
            ec2.authorize_security_group_ingress(GroupId=f.resource_id, IpPermissions=[{
                k: v for k, v in perm.items() if k != "Ipv6Ranges"} | {"IpRanges": [{"CidrIp": admin_cidr, "Description": "self-heal admin range"}]}])
    return f"revoked {revoked} internet-facing ingress rule(s)" + (f", re-granted to {admin_cidr}" if admin_cidr else "")


def _fix_open_ssh(sess, f):
    return _revoke_world(sess, f, lambda p: _covers(p, 22))


def _fix_open_rdp(sess, f):
    return _revoke_world(sess, f, lambda p: _covers(p, 3389))


def _fix_open_all(sess, f):
    return _revoke_world(sess, f, _all_ports)


# ------------------------------------------------------------------ CloudTrail
def _trail_bucket(sess) -> str:
    s3 = sess.client("s3")
    acct = sess.client("sts").get_caller_identity()["Account"]
    name = f"selfheal-cloudtrail-{acct}"
    try:
        s3.head_bucket(Bucket=name)
    except ClientError:
        s3.create_bucket(Bucket=name)
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        # the healer must not create new findings: make its own log bucket compliant
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]})
    return name


def _enable_cloudtrail(sess, f: Finding) -> str:
    ct = sess.client("cloudtrail")
    if f.rule == Rule.CLOUDTRAIL_MISSING:
        name = "selfheal-org-trail"
        ct.create_trail(Name=name, S3BucketName=_trail_bucket(sess), IsMultiRegionTrail=True,
                        EnableLogFileValidation=True, IncludeGlobalServiceEvents=True)
        ct.start_logging(Name=name)
        return f"created multi-region trail {name} and started logging"
    ct.start_logging(Name=f.resource_id)
    return "logging started"


def _set_trail_multiregion(sess, f: Finding) -> str:
    sess.client("cloudtrail").update_trail(Name=f.resource_id, IsMultiRegionTrail=True, IncludeGlobalServiceEvents=True)
    return "trail set to multi-region"


def _enable_trail_validation(sess, f: Finding) -> str:
    sess.client("cloudtrail").update_trail(Name=f.resource_id, EnableLogFileValidation=True)
    return "log file validation enabled"


# ------------------------------------------------------------------ IAM (high risk)
def _quarantine_admin_policy(sess, f: Finding) -> str:
    """Replace '*' admin statements with an explicit deny-all version. HIGH risk."""
    import json
    iam = sess.client("iam")
    deny = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    if f.resource_type == "iam_policy":
        vs = iam.list_policy_versions(PolicyArn=f.resource_id)["Versions"]
        if len(vs) >= 5:
            old = sorted([v for v in vs if not v["IsDefaultVersion"]], key=lambda v: v["CreateDate"])[0]
            iam.delete_policy_version(PolicyArn=f.resource_id, VersionId=old["VersionId"])
        iam.create_policy_version(PolicyArn=f.resource_id, PolicyDocument=deny, SetAsDefault=True)
        return "new default policy version denies all (old version kept for rollback)"
    _, rest = f.resource_id.split(":", 1)
    kind_principal, pname = rest.rsplit("/", 1)
    kind, principal = kind_principal.split("/", 1)
    if kind == "role":
        iam.put_role_policy(RoleName=principal, PolicyName=pname, PolicyDocument=deny)
    else:
        iam.put_user_policy(UserName=principal, PolicyName=pname, PolicyDocument=deny)
    return "inline policy replaced with deny-all"


TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("fix_s3_public_access", Rule.S3_PUBLIC_ACCESS,
         ("s3:PutBucketPublicAccessBlock", "s3:PutBucketAcl"), "LOW",
         "Turn on all four S3 Block Public Access settings and reset a public ACL to private.", _fix_s3_public_access),
    Tool("enable_s3_versioning", Rule.S3_VERSIONING_DISABLED,
         ("s3:PutBucketVersioning",), "LOW", "Enable object versioning on the bucket.", _enable_s3_versioning),
    Tool("enable_s3_kms_encryption", Rule.S3_NO_KMS_ENCRYPTION,
         ("s3:PutEncryptionConfiguration",), "LOW", "Set default SSE-KMS encryption on the bucket.", _enable_s3_kms),
    Tool("fix_open_ssh", Rule.SG_OPEN_SSH,
         ("ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress"), "MEDIUM",
         "Revoke 0.0.0.0/0 and ::/0 ingress that covers TCP 22.", _fix_open_ssh),
    Tool("fix_open_rdp", Rule.SG_OPEN_RDP,
         ("ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress"), "MEDIUM",
         "Revoke 0.0.0.0/0 and ::/0 ingress that covers TCP 3389.", _fix_open_rdp),
    Tool("fix_open_all_ingress", Rule.SG_OPEN_ALL_PORTS,
         ("ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress"), "MEDIUM",
         "Revoke internet ingress that opens every port.", _fix_open_all),
    Tool("enable_cloudtrail", Rule.CLOUDTRAIL_NOT_LOGGING,
         ("cloudtrail:StartLogging", "cloudtrail:CreateTrail", "s3:CreateBucket", "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration"), "LOW",
         "Start logging on a trail, or create a multi-region trail if none exists.", _enable_cloudtrail),
    Tool("set_cloudtrail_multiregion", Rule.CLOUDTRAIL_NOT_MULTI_REGION,
         ("cloudtrail:UpdateTrail",), "LOW", "Make the trail record all regions.", _set_trail_multiregion),
    Tool("enable_cloudtrail_log_validation", Rule.CLOUDTRAIL_NO_LOG_VALIDATION,
         ("cloudtrail:UpdateTrail",), "LOW", "Turn on CloudTrail log file integrity validation.", _enable_trail_validation),
    Tool("quarantine_admin_policy", Rule.IAM_ADMIN_WILDCARD,
         ("iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:PutRolePolicy", "iam:PutUserPolicy"), "HIGH",
         "Replace an Action:'*' policy with deny-all. Needs human approval.", _quarantine_admin_policy),
]}

# CLOUDTRAIL_MISSING is fixed by the same approved tool as NOT_LOGGING
ALLOWED_FOR: dict[Rule, set[str]] = {}
for _t in TOOLS.values():
    ALLOWED_FOR.setdefault(_t.fixes, set()).add(_t.name)
ALLOWED_FOR[Rule.CLOUDTRAIL_MISSING] = {"enable_cloudtrail"}


def all_tool_actions() -> list[str]:
    return sorted({a for t in TOOLS.values() for a in t.actions} | {"sts:GetCallerIdentity"})
