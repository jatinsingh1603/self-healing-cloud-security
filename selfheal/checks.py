"""Detection stage: read live AWS configuration and emit findings.

Every check is written as a per-resource function so the verifier can
re-run exactly the same logic on exactly one resource after a fix.
"""
from __future__ import annotations

import json
from typing import Callable, Iterable
from urllib.parse import unquote

from botocore.exceptions import ClientError

from .model import Finding, Rule

WORLD = {"0.0.0.0/0", "::/0"}
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


def _tag_ref(tags: list[dict] | None) -> str | None:
    for t in tags or []:
        if t.get("Key") == "tf_address":
            return t.get("Value")
    return None


# ----------------------------------------------------------------- S3
def check_bucket(s3, bucket: str, ref: str | None = None) -> list[Finding]:
    out: list[Finding] = []

    # Public access: block config, ACL grants and bucket policy
    pab = {}
    try:
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if _code(e) != "NoSuchPublicAccessBlockConfiguration":
            raise
    pab_ok = all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))

    acl_public = False
    try:
        grants = s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
        acl_public = any(g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES for g in grants)
    except ClientError:
        pass

    policy_public = False
    try:
        pol = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        for st in pol.get("Statement", []):
            p = st.get("Principal")
            if st.get("Effect") == "Allow" and (p == "*" or (isinstance(p, dict) and p.get("AWS") in ("*", ["*"]))):
                policy_public = True
    except ClientError:
        pass

    if not pab_ok:
        out.append(Finding(Rule.S3_PUBLIC_ACCESS, "s3_bucket", bucket, {
            "public_access_block": pab or None,
            "acl_public": acl_public,
            "policy_public": policy_public,
        }, ref))

    try:
        v = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    except ClientError:
        v = None
    if v != "Enabled":
        out.append(Finding(Rule.S3_VERSIONING_DISABLED, "s3_bucket", bucket, {"versioning": v or "Never enabled"}, ref))

    algo = None
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
        algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    except (ClientError, KeyError, IndexError):
        pass
    if algo not in ("aws:kms", "aws:kms:dsse"):
        out.append(Finding(Rule.S3_NO_KMS_ENCRYPTION, "s3_bucket", bucket, {"sse_algorithm": algo or "none"}, ref))
    return out


def _bucket_ref(s3, bucket: str) -> str | None:
    try:
        return _tag_ref(s3.get_bucket_tagging(Bucket=bucket).get("TagSet"))
    except ClientError:
        return None


# ----------------------------------------------------------------- Security groups
def _covers(perm: dict, port: int) -> bool:
    if perm.get("IpProtocol") in ("-1", -1):
        return True
    if perm.get("IpProtocol") not in ("tcp", "6"):
        return False
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


def _world_ranges(perm: dict) -> list[str]:
    r = [x["CidrIp"] for x in perm.get("IpRanges", []) if x.get("CidrIp") in WORLD]
    r += [x["CidrIpv6"] for x in perm.get("Ipv6Ranges", []) if x.get("CidrIpv6") in WORLD]
    return r


def _all_ports(perm: dict) -> bool:
    if perm.get("IpProtocol") in ("-1", -1):
        return True
    return perm.get("FromPort") == 0 and perm.get("ToPort") == 65535


def check_security_group(sg: dict) -> list[Finding]:
    out: list[Finding] = []
    ref = _tag_ref(sg.get("Tags"))
    gid = sg["GroupId"]
    for rule, test in (
        (Rule.SG_OPEN_SSH, lambda p: _covers(p, 22)),
        (Rule.SG_OPEN_RDP, lambda p: _covers(p, 3389)),
        (Rule.SG_OPEN_ALL_PORTS, _all_ports),
    ):
        bad = [
            {"protocol": p.get("IpProtocol"), "from": p.get("FromPort"), "to": p.get("ToPort"), "cidrs": _world_ranges(p)}
            for p in sg.get("IpPermissions", []) if test(p) and _world_ranges(p)
        ]
        if bad:
            out.append(Finding(rule, "security_group", gid, {"group_name": sg.get("GroupName"), "open_rules": bad}, ref))
    return out


def get_security_group(ec2, group_id: str) -> dict | None:
    try:
        return ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    except ClientError:
        return None


# ----------------------------------------------------------------- CloudTrail
def check_trail(ct, trail: dict) -> list[Finding]:
    out: list[Finding] = []
    name = trail["Name"]
    ref = None
    try:
        tags = ct.list_tags(ResourceIdList=[trail["TrailARN"]])["ResourceTagList"]
        ref = _tag_ref(tags[0].get("TagsList")) if tags else None
    except (ClientError, KeyError):
        pass
    try:
        logging = ct.get_trail_status(Name=name).get("IsLogging", False)
    except ClientError:
        logging = False
    if not logging:
        out.append(Finding(Rule.CLOUDTRAIL_NOT_LOGGING, "cloudtrail", name, {"is_logging": False}, ref))
    if not trail.get("IsMultiRegionTrail"):
        out.append(Finding(Rule.CLOUDTRAIL_NOT_MULTI_REGION, "cloudtrail", name, {"is_multi_region": False}, ref))
    if not trail.get("LogFileValidationEnabled"):
        out.append(Finding(Rule.CLOUDTRAIL_NO_LOG_VALIDATION, "cloudtrail", name, {"log_file_validation": False}, ref))
    return out


def get_trail(ct, name: str) -> dict | None:
    # Filter by name ourselves: never trust the API to have applied the filter
    # (the emulator ignores trailNameList and returns every trail).
    for t in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
        if t.get("Name") == name or t.get("TrailARN") == name:
            return t
    return None


# ----------------------------------------------------------------- IAM
def _is_admin(doc: dict) -> bool:
    sts = doc.get("Statement", [])
    if isinstance(sts, dict):
        sts = [sts]
    for st in sts:
        if st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if "*" in actions:
            return True
    return False


def _doc(raw) -> dict:
    if isinstance(raw, str):
        return json.loads(unquote(raw))
    return raw


def check_policy(iam, arn: str, ref: str | None = None) -> list[Finding]:
    p = iam.get_policy(PolicyArn=arn)["Policy"]
    ver = iam.get_policy_version(PolicyArn=arn, VersionId=p["DefaultVersionId"])["PolicyVersion"]
    if _is_admin(_doc(ver["Document"])):
        ref = ref or _tag_ref(p.get("Tags"))
        return [Finding(Rule.IAM_ADMIN_WILDCARD, "iam_policy", arn, {"policy_name": p["PolicyName"], "version": p["DefaultVersionId"]}, ref)]
    return []


def check_inline(iam, kind: str, principal: str, policy_name: str, ref: str | None = None) -> list[Finding]:
    getter = iam.get_role_policy if kind == "role" else iam.get_user_policy
    kw = {"RoleName": principal} if kind == "role" else {"UserName": principal}
    doc = _doc(getter(PolicyName=policy_name, **kw)["PolicyDocument"])
    if _is_admin(doc):
        rid = f"inline:{kind}/{principal}/{policy_name}"
        return [Finding(Rule.IAM_ADMIN_WILDCARD, "iam_inline_policy", rid, {"principal": f"{kind}/{principal}", "policy_name": policy_name}, ref)]
    return []


# ----------------------------------------------------------------- full scan
def scan(session, rules: Iterable[Rule] | None = None) -> list[Finding]:
    """Scan the whole account. `session` is a GuardedSession (read-only)."""
    wanted = set(rules) if rules else set(Rule)
    s3, ec2, ct, iam = (session.client(x) for x in ("s3", "ec2", "cloudtrail", "iam"))
    findings: list[Finding] = []

    for b in s3.list_buckets().get("Buckets", []):
        findings += check_bucket(s3, b["Name"], _bucket_ref(s3, b["Name"]))

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            findings += check_security_group(sg)

    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        findings.append(Finding(Rule.CLOUDTRAIL_MISSING, "account", "account", {"trails": 0}))
    for t in trails:
        findings += check_trail(ct, t)

    for p in iam.list_policies(Scope="Local").get("Policies", []):
        findings += check_policy(iam, p["Arn"])
    for r in iam.list_roles().get("Roles", []):
        for pn in iam.list_role_policies(RoleName=r["RoleName"]).get("PolicyNames", []):
            findings += check_inline(iam, "role", r["RoleName"], pn, _tag_ref(iam.list_role_tags(RoleName=r["RoleName"]).get("Tags")))
    for u in iam.list_users().get("Users", []):
        for pn in iam.list_user_policies(UserName=u["UserName"]).get("PolicyNames", []):
            findings += check_inline(iam, "user", u["UserName"], pn, _tag_ref(iam.list_user_tags(UserName=u["UserName"]).get("Tags")))

    return [f for f in findings if f.rule in wanted]


def recheck(session, finding: Finding) -> bool:
    """Independent re-check of one finding. Returns True if the issue is GONE."""
    rt, rid, rule = finding.resource_type, finding.resource_id, finding.rule
    if rt == "s3_bucket":
        current = check_bucket(session.client("s3"), rid)
    elif rt == "security_group":
        sg = get_security_group(session.client("ec2"), rid)
        current = check_security_group(sg) if sg else []
    elif rt == "cloudtrail":
        ct = session.client("cloudtrail")
        t = get_trail(ct, rid)
        current = check_trail(ct, t) if t else [Finding(rule, rt, rid)]
    elif rt == "account":
        current = [] if session.client("cloudtrail").describe_trails().get("trailList") else [finding]
    elif rt == "iam_policy":
        current = check_policy(session.client("iam"), rid)
    elif rt == "iam_inline_policy":
        _, rest = rid.split(":", 1)
        kind_principal, pname = rest.rsplit("/", 1)
        kind, principal = kind_principal.split("/", 1)
        try:
            current = check_inline(session.client("iam"), kind, principal, pname)
        except ClientError:
            current = []
    else:
        raise ValueError(rt)
    return not any(f.rule == rule for f in current)
