"""Deploy a public Terraform dataset into an (emulated) AWS account.

The datasets (TerraGoat, sadcloud, CloudGoat) are Terraform. We parse every
module directory, resolve simple expressions (variable defaults, locals,
`!`, `&&`, `||`, ternaries), then create the in-scope resources through
boto3 exactly as `terraform apply` would. Each created resource is tagged
with `tf_address = <file>::<type.name>` so findings can be scored against
labels that refer to the Terraform source.

In-scope resource types: S3 buckets (+ acl / public access block /
versioning / encryption / policy companions), security groups (+ rules),
CloudTrail trails, IAM managed and inline policies.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field

import hcl2

UNKNOWN = object()


# ---------------------------------------------------------------- expression eval
_REF = re.compile(r"^(var|local)\.([A-Za-z0-9_-]+)$")


def _first(v):
    return v[0] if isinstance(v, list) and len(v) == 1 else v


class Ctx:
    def __init__(self, variables: dict, locals_: dict):
        self.vars = variables
        self.locals = locals_

    def ev(self, v, depth=0):
        """Evaluate an attribute value. Returns UNKNOWN when not resolvable."""
        v = _first(v)
        if depth > 8:
            return UNKNOWN
        if isinstance(v, (bool, int, float)) or v is None:
            return v
        if isinstance(v, list):
            return [self.ev(x, depth + 1) for x in v]
        if isinstance(v, dict):
            return v
        if not isinstance(v, str):
            return UNKNOWN
        s = v.strip()
        if s.startswith("${") and s.endswith("}") and s.count("${") == 1:
            return self.expr(s[2:-1].strip(), depth)
        if "${" in s:
            return re.sub(r"\$\{([^}]*)\}", lambda m: str(self._s(self.expr(m.group(1), depth))), s)
        return s

    def _s(self, x):
        return "x" if x is UNKNOWN else x

    def expr(self, e: str, depth=0):
        e = e.strip()
        if e in ("true", "True"):
            return True
        if e in ("false", "False"):
            return False
        if e == "null":
            return None
        if re.fullmatch(r"-?\d+", e):
            return int(e)
        if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
            return e[1:-1]
        m = _REF.match(e)
        if m:
            src = self.vars if m.group(1) == "var" else self.locals
            return self.ev(src[m.group(2)], depth + 1) if m.group(2) in src else UNKNOWN
        # ternary  cond ? a : b   (top-level only)
        t = re.fullmatch(r"(.+?)\s*\?\s*(.+?)\s*:\s*(.+)", e)
        if t:
            c = self.expr(t.group(1), depth + 1)
            if c is UNKNOWN:
                return UNKNOWN
            return self.expr(t.group(2) if c else t.group(3), depth + 1)
        for op, fn in (("||", any), ("&&", all)):
            if op in e:
                parts = [self.expr(p, depth + 1) for p in e.split(op)]
                if any(p is UNKNOWN for p in parts):
                    return UNKNOWN
                return fn(bool(p) for p in parts)
        if e.startswith("!"):
            x = self.expr(e[1:].strip().strip("()"), depth + 1)
            return UNKNOWN if x is UNKNOWN else (not x)
        if e.startswith("(") and e.endswith(")"):
            return self.expr(e[1:-1], depth + 1)
        return UNKNOWN


def _bool(x, default):
    if x is UNKNOWN or x is None:
        return default
    if isinstance(x, str):
        return x.lower() == "true"
    return bool(x)


def _ref(v, rtype) -> str | None:
    s = json.dumps(v) if not isinstance(v, str) else v
    m = re.search(rf"{rtype}\.([A-Za-z0-9_-]+)", s)
    return m.group(1) if m else None


# ---------------------------------------------------------------- parsing
@dataclass
class Module:
    dataset: str
    rel_dir: str
    resources: list = field(default_factory=list)    # (type, name, attrs, rel_file)
    data: dict = field(default_factory=dict)          # (type, name) -> attrs
    ctx: Ctx | None = None


def parse_dataset(root: str, dataset: str) -> list[Module]:
    modules = []
    for d, _, files in sorted(os.walk(root)):
        if "/.git" in d or "/.terraform" in d:
            continue
        tfs = sorted(f for f in files if f.endswith(".tf"))
        if not tfs:
            continue
        rel_dir = "/" + os.path.relpath(d, root).replace("./", "").strip(".")
        rel_dir = rel_dir if rel_dir != "/" else ""
        mod = Module(dataset, rel_dir)
        variables, locals_ = {}, {}
        for f in tfs:
            try:
                with open(os.path.join(d, f)) as fh:
                    doc = hcl2.load(fh)
            except Exception:
                continue
            rel_file = f"{rel_dir}/{f}"
            for vb in doc.get("variable", []):
                for k, v in vb.items():
                    variables[k] = v.get("default", [UNKNOWN])
            for lb in doc.get("locals", []):
                locals_.update(lb)
            for rb in doc.get("resource", []):
                for rtype, named in rb.items():
                    for name, attrs in named.items():
                        mod.resources.append((rtype, name, attrs, rel_file))
            for db in doc.get("data", []):
                for dtype, named in db.items():
                    for name, attrs in named.items():
                        mod.data[(dtype, name)] = attrs
        mod.ctx = Ctx(variables, locals_)
        if mod.resources:
            modules.append(mod)
    return modules


# ---------------------------------------------------------------- policy documents
def _hcl_obj_to_json(s: str):
    """Best effort for `jsonencode({...})` bodies rendered by hcl2 0.4."""
    body = s.strip()
    body = re.sub(r"^\$\{jsonencode\(", "", body)
    body = re.sub(r"\)\}$", "", body)
    body = body.replace("'", '"')
    body = re.sub(r'"\$\{[^}]*\}"', '"x"', body)
    body = re.sub(r"\bTrue\b", "true", body)
    body = re.sub(r"\bFalse\b", "false", body)
    try:
        return json.loads(body)
    except Exception:
        return None


def policy_doc(mod: Module, raw) -> dict | None:
    raw = _first(raw)
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    dref = re.search(r"data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)", s)
    if dref:
        d = mod.data.get(("aws_iam_policy_document", dref.group(1)))
        if not d:
            return None
        stmts = []
        for st in d.get("statement", []):
            acts = mod.ctx.ev(st.get("actions", [[]]))
            acts = acts if isinstance(acts, list) else [acts]
            stmts.append({"Effect": _first(st.get("effect", ["Allow"])) or "Allow",
                          "Action": [a if isinstance(a, str) else "x" for a in acts] or ["x"],
                          "Resource": "*"})
        return {"Version": "2012-10-17", "Statement": stmts}
    if "jsonencode" in s:
        return _hcl_obj_to_json(s)
    if "file(" in s or "templatefile(" in s:
        return None
    s = re.sub(r"\$\{[^}]*\}", "x", s)
    try:
        return json.loads(s)
    except Exception:
        return None


# ---------------------------------------------------------------- deploy
def _slug(*parts, maxlen=63) -> str:
    raw = "-".join(parts).lower()
    s = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
    h = hashlib.sha1(raw.encode()).hexdigest()[:6]
    s = s[: maxlen - 7].strip("-")
    return f"{s}-{h}"


@dataclass
class DeployReport:
    created: dict = field(default_factory=dict)        # tf key -> aws id
    aux_to_primary: dict = field(default_factory=dict)  # companion key -> primary key
    skipped: list = field(default_factory=list)


def deploy(modules: list[Module], region: str = "us-east-1") -> DeployReport:
    import boto3
    from botocore.exceptions import ClientError
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    ct = boto3.client("cloudtrail", region_name=region)
    iam = boto3.client("iam", region_name=region)
    rep = DeployReport()

    sink = "dataset-trail-sink"
    try:
        s3.create_bucket(Bucket=sink)
    except ClientError:
        pass
    # harness-only bucket for trails: fully compliant so it adds no findings of its own
    s3.put_public_access_block(Bucket=sink, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket=sink, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket=sink, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})

    for mod in modules:
        c = mod.ctx
        by_type: dict[str, dict] = {}
        for rtype, name, attrs, rfile in mod.resources:
            by_type.setdefault(rtype, {})[name] = (attrs, rfile)
        key = lambda rtype, name: f"{by_type[rtype][name][1]}::{rtype}.{name}"

        # ---------- S3
        buckets = {}
        for name, (a, rfile) in by_type.get("aws_s3_bucket", {}).items():
            k = key("aws_s3_bucket", name)
            b = _slug(mod.dataset[:6], mod.rel_dir[-20:], name)
            s3.create_bucket(Bucket=b)
            s3.put_bucket_tagging(Bucket=b, Tagging={"TagSet": [{"Key": "tf_address", "Value": k}]})
            # AWS default for new buckets since 2023: owner-enforced, BPA on. Terraform datasets
            # predate that and checkov evaluates them as written, so we mirror "as written".
            acl = c.ev(a.get("acl", [None]))
            if acl in ("public-read", "public-read-write", "authenticated-read"):
                s3.put_bucket_acl(Bucket=b, ACL=acl)
            ver = a.get("versioning")
            if ver and _bool(c.ev(ver[0].get("enabled", [False])), False):
                s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
            sse = a.get("server_side_encryption_configuration")
            if sse:
                algo = json.dumps(sse)
                s3.put_bucket_encryption(Bucket=b, ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms" if "aws:kms" in algo else "AES256"}}]})
            pol = policy_doc(mod, a.get("policy")) if a.get("policy") else None
            if pol:
                try:
                    s3.put_bucket_policy(Bucket=b, Policy=json.dumps(pol))
                except ClientError:
                    pass
            buckets[name] = b
            rep.created[k] = b

        def bucket_of(a):
            n = _ref(a.get("bucket"), "aws_s3_bucket")
            return (n, buckets.get(n)) if n else (None, None)

        for name, (a, rfile) in by_type.get("aws_s3_bucket_public_access_block", {}).items():
            n, b = bucket_of(a)
            if not b:
                rep.skipped.append(key("aws_s3_bucket_public_access_block", name)); continue
            cfg = {k2: _bool(c.ev(a.get(t, [False])), False) for k2, t in (
                ("BlockPublicAcls", "block_public_acls"), ("IgnorePublicAcls", "ignore_public_acls"),
                ("BlockPublicPolicy", "block_public_policy"), ("RestrictPublicBuckets", "restrict_public_buckets"))}
            s3.put_public_access_block(Bucket=b, PublicAccessBlockConfiguration=cfg)
            rep.aux_to_primary[key("aws_s3_bucket_public_access_block", name)] = key("aws_s3_bucket", n)
        for name, (a, rfile) in by_type.get("aws_s3_bucket_acl", {}).items():
            n, b = bucket_of(a)
            if not b:
                continue
            acl = c.ev(a.get("acl", [None]))
            if acl in ("public-read", "public-read-write", "authenticated-read"):
                s3.put_bucket_acl(Bucket=b, ACL=acl)
            rep.aux_to_primary[key("aws_s3_bucket_acl", name)] = key("aws_s3_bucket", n)
        for name, (a, rfile) in by_type.get("aws_s3_bucket_versioning", {}).items():
            n, b = bucket_of(a)
            if not b:
                continue
            st = c.ev((a.get("versioning_configuration") or [{}])[0].get("status", ["Suspended"]))
            if st == "Enabled":
                s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
            rep.aux_to_primary[key("aws_s3_bucket_versioning", name)] = key("aws_s3_bucket", n)
        for name, (a, rfile) in by_type.get("aws_s3_bucket_server_side_encryption_configuration", {}).items():
            n, b = bucket_of(a)
            if not b:
                continue
            kms = "aws:kms" in json.dumps(a)
            s3.put_bucket_encryption(Bucket=b, ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms" if kms else "AES256"}}]})
            rep.aux_to_primary[key("aws_s3_bucket_server_side_encryption_configuration", name)] = key("aws_s3_bucket", n)
        for name, (a, rfile) in by_type.get("aws_s3_bucket_policy", {}).items():
            n, b = bucket_of(a)
            if not b:
                continue
            pol = policy_doc(mod, a.get("policy"))
            if pol:
                try:
                    s3.put_bucket_policy(Bucket=b, Policy=json.dumps(pol))
                except ClientError:
                    pass
            rep.aux_to_primary[key("aws_s3_bucket_policy", name)] = key("aws_s3_bucket", n)

        # ---------- Security groups
        sgs = {}

        def perm_from(proto, fp, tp, cidrs, v6):
            proto = str(proto).lower() if proto not in (None, UNKNOWN) else "tcp"
            proto = {"all": "-1", "6": "tcp", "17": "udp", "-1": "-1"}.get(proto, proto)
            p = {"IpProtocol": proto}
            if proto != "-1":
                try:
                    p["FromPort"], p["ToPort"] = int(fp), int(tp)
                except (TypeError, ValueError):
                    return None
            cidrs = [x for x in (cidrs or []) if isinstance(x, str) and "/" in x]
            v6 = [x for x in (v6 or []) if isinstance(x, str) and "/" in x]
            if not cidrs and not v6:
                return None
            if cidrs:
                p["IpRanges"] = [{"CidrIp": x} for x in cidrs]
            if v6:
                p["Ipv6Ranges"] = [{"CidrIpv6": x} for x in v6]
            return p

        def authorize(gid, p):
            try:
                ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[p])
            except ClientError:
                pass

        def lst(x):
            x = c.ev(x)
            return x if isinstance(x, list) else ([] if x in (UNKNOWN, None) else [x])

        for name, (a, rfile) in by_type.get("aws_security_group", {}).items():
            k = key("aws_security_group", name)
            gname = _slug(mod.dataset[:6], mod.rel_dir[-20:], name, maxlen=200)
            gid = ec2.create_security_group(GroupName=gname, Description="dataset sg",
                                            TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "tf_address", "Value": k}]}])["GroupId"]
            for ing in a.get("ingress", []):
                p = perm_from(c.ev(ing.get("protocol", ["tcp"])), c.ev(ing.get("from_port", [None])), c.ev(ing.get("to_port", [None])),
                              lst(ing.get("cidr_blocks", [[]])), lst(ing.get("ipv6_cidr_blocks", [[]])))
                if p:
                    authorize(gid, p)
            sgs[name] = gid
            rep.created[k] = gid

        for name, (a, rfile) in by_type.get("aws_security_group_rule", {}).items():
            if c.ev(a.get("type", ["ingress"])) != "ingress":
                continue
            n = _ref(a.get("security_group_id"), "aws_security_group")
            if n not in sgs:
                rep.skipped.append(key("aws_security_group_rule", name)); continue
            p = perm_from(c.ev(a.get("protocol", ["tcp"])), c.ev(a.get("from_port", [None])), c.ev(a.get("to_port", [None])),
                          lst(a.get("cidr_blocks", [[]])), lst(a.get("ipv6_cidr_blocks", [[]])))
            if p:
                authorize(sgs[n], p)
            rep.aux_to_primary[key("aws_security_group_rule", name)] = key("aws_security_group", n)

        for name, (a, rfile) in by_type.get("aws_vpc_security_group_ingress_rule", {}).items():
            n = _ref(a.get("security_group_id"), "aws_security_group")
            if n not in sgs:
                continue
            p = perm_from(c.ev(a.get("ip_protocol", ["tcp"])), c.ev(a.get("from_port", [None])), c.ev(a.get("to_port", [None])),
                          [c.ev(a.get("cidr_ipv4", [None]))], [c.ev(a.get("cidr_ipv6", [None]))])
            if p:
                authorize(sgs[n], p)
            rep.aux_to_primary[key("aws_vpc_security_group_ingress_rule", name)] = key("aws_security_group", n)

        # ---------- CloudTrail
        for name, (a, rfile) in by_type.get("aws_cloudtrail", {}).items():
            k = key("aws_cloudtrail", name)
            tname = _slug(mod.dataset[:6], mod.rel_dir[-20:], name, maxlen=120)
            ct.create_trail(Name=tname, S3BucketName=sink,
                            IsMultiRegionTrail=_bool(c.ev(a.get("is_multi_region_trail", [False])), False),
                            EnableLogFileValidation=_bool(c.ev(a.get("enable_log_file_validation", [False])), False),
                            TagsList=[{"Key": "tf_address", "Value": k}])
            if _bool(c.ev(a.get("enable_logging", [True])), True):
                ct.start_logging(Name=tname)
            rep.created[k] = tname

        # ---------- IAM
        for name, (a, rfile) in by_type.get("aws_iam_policy", {}).items():
            k = key("aws_iam_policy", name)
            doc = policy_doc(mod, a.get("policy"))
            if not doc:
                rep.skipped.append(k); continue
            try:
                arn = iam.create_policy(PolicyName=_slug(mod.dataset[:6], name, maxlen=120), PolicyDocument=json.dumps(doc),
                                        Tags=[{"Key": "tf_address", "Value": k}])["Policy"]["Arn"]
                rep.created[k] = arn
            except ClientError:
                rep.skipped.append(k)
        for kind in ("role", "user"):
            for name, (a, rfile) in by_type.get(f"aws_iam_{kind}_policy", {}).items():
                k = key(f"aws_iam_{kind}_policy", name)
                doc = policy_doc(mod, a.get("policy"))
                if not doc:
                    rep.skipped.append(k); continue
                pname = _slug(mod.dataset[:6], name, maxlen=60)
                tags = [{"Key": "tf_address", "Value": k}]
                try:
                    if kind == "role":
                        iam.create_role(RoleName=pname, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}), Tags=tags)
                        iam.put_role_policy(RoleName=pname, PolicyName=name, PolicyDocument=json.dumps(doc))
                    else:
                        iam.create_user(UserName=pname, Tags=tags)
                        iam.put_user_policy(UserName=pname, PolicyName=name, PolicyDocument=json.dumps(doc))
                    rep.created[k] = pname
                except ClientError:
                    rep.skipped.append(k)
    return rep
