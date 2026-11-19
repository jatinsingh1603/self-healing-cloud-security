"""Ground-truth labels from Checkov, the open-source reference scanner.

For each of our rules we list the Checkov check IDs that test the same
property. A resource is labelled positive for a rule if ANY of those checks
failed on it (or on one of its companion resources, e.g. an
aws_s3_bucket_public_access_block that belongs to the bucket), and negative
if they all passed. Resources Checkov never evaluated for a rule are outside
that rule's universe and are not scored.
"""
from __future__ import annotations

import json
import re
import subprocess

from .model import Rule

CHECKOV_MAP: dict[Rule, set[str]] = {
    Rule.S3_PUBLIC_ACCESS: {"CKV2_AWS_6", "CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56", "CKV_AWS_20", "CKV_AWS_57"},
    Rule.S3_VERSIONING_DISABLED: {"CKV_AWS_21"},
    Rule.S3_NO_KMS_ENCRYPTION: {"CKV_AWS_145"},
    Rule.SG_OPEN_SSH: {"CKV_AWS_24"},
    Rule.SG_OPEN_RDP: {"CKV_AWS_25"},
    Rule.SG_OPEN_ALL_PORTS: {"CKV_AWS_277"},
    Rule.CLOUDTRAIL_NOT_MULTI_REGION: {"CKV_AWS_67"},
    Rule.CLOUDTRAIL_NO_LOG_VALIDATION: {"CKV_AWS_36"},
    Rule.IAM_ADMIN_WILDCARD: {"CKV_AWS_62", "CKV_AWS_63"},
}
SCORED_RULES = list(CHECKOV_MAP)
_IDX = re.compile(r"\[[^\]]*\]")


def run_checkov(path: str, out_json: str) -> None:
    ids = sorted({i for s in CHECKOV_MAP.values() for i in s})
    with open(out_json, "w") as f:
        subprocess.run(["checkov", "-d", path, "--framework", "terraform", "-o", "json",
                        "--check", ",".join(ids), "--download-external-modules", "false"],
                       stdout=f, stderr=subprocess.DEVNULL)


def _key(r: dict) -> str:
    addr = _IDX.sub("", r["resource"])
    parts = addr.split(".")
    if parts[0] == "module":          # module.x.aws_y.z -> aws_y.z (file path disambiguates)
        parts = parts[-2:]
    return f"{r['file_path']}::{'.'.join(parts[-2:])}"


def load_labels(checkov_json: str, aux_to_primary: dict[str, str]) -> dict[Rule, dict[str, int]]:
    data = json.load(open(checkov_json))
    blocks = data if isinstance(data, list) else [data]
    labels: dict[Rule, dict[str, int]] = {r: {} for r in CHECKOV_MAP}
    rev = {cid: r for r, ids in CHECKOV_MAP.items() for cid in ids}
    for blk in blocks:
        if blk.get("check_type") not in (None, "terraform"):
            continue
        res = blk.get("results", {})
        for outcome, val in (("passed_checks", 0), ("failed_checks", 1)):
            for r in res.get(outcome, []):
                rule = rev.get(r["check_id"])
                if not rule:
                    continue
                k = _key(r)
                k = aux_to_primary.get(k, k)
                labels[rule][k] = max(labels[rule].get(k, 0), val)
    return labels


def score(labels: dict[Rule, dict[str, int]], predicted: dict[Rule, set[str]]) -> dict:
    per_rule, tot = {}, dict(tp=0, fp=0, fn=0, tn=0)
    for rule in SCORED_RULES:
        u = labels.get(rule, {})
        if not u:
            continue
        p = predicted.get(rule, set())
        tp = sum(1 for k, y in u.items() if y and k in p)
        fn = sum(1 for k, y in u.items() if y and k not in p)
        fp = sum(1 for k, y in u.items() if not y and k in p)
        tn = sum(1 for k, y in u.items() if not y and k not in p)
        per_rule[rule.value] = _metrics(tp, fp, fn, tn)
        for n, v in zip(("tp", "fp", "fn", "tn"), (tp, fp, fn, tn)):
            tot[n] += v
    return {"per_rule": per_rule, "overall": _metrics(**tot)}


def _metrics(tp, fp, fn, tn) -> dict:
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / (tp + fp + fn + tn) if tp + fp + fn + tn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": tp + fp + fn + tn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "accuracy": round(acc, 4)}
