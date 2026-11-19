"""Run every experiment and write results/results.json.

    python experiments/run_all.py --datasets-dir ../datasets --runs 5

E1 Detection accuracy on 3 public datasets (vs Checkov, raw and adjudicated)
E2 End-to-end remediation: healed rate + stage timings over repeated runs
E3 AI selector robustness: noisy selector x {guardrail, verification} ablation
E4 Fault injection: stale reads, partial fixes, transient errors
E5 Least privilege: out-of-policy API calls attempted vs blocked
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import statistics as st
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="us-east-1")

from moto import mock_aws  # noqa: E402

from selfheal import checks, labels, loader  # noqa: E402
from selfheal.decide import NoisySelector, RuleSelector  # noqa: E402
from selfheal.engine import Config, SelfHealer  # noqa: E402
from selfheal.faults import FaultyTools, StaleReads  # noqa: E402
from selfheal.guard import GuardedSession, PermissionDenied, reader_identity, remediator_identity  # noqa: E402
from selfheal.model import Rule, Status  # noqa: E402
from selfheal.tools import TOOLS, all_tool_actions  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DATASETS = {
    "terragoat": {"repo": "https://github.com/bridgecrewio/terragoat", "path": "terraform/aws", "by": "Bridgecrew (Palo Alto Networks)"},
    "sadcloud": {"repo": "https://github.com/nccgroup/sadcloud", "path": "", "by": "NCC Group"},
    "cloudgoat": {"repo": "https://github.com/RhinoSecurityLabs/cloudgoat", "path": "cloudgoat/scenarios/aws", "by": "Rhino Security Labs"},
}
FAST = Config(verify_backoff_s=0.0)


def git_rev(path):
    try:
        import subprocess
        return subprocess.check_output(["git", "-C", path, "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def predicted(findings):
    p = collections.defaultdict(set)
    for f in findings:
        if f.source_ref:
            p[f.rule].add(f.source_ref)
    return p


def adjudicate(ds, lab, mods):
    adj = json.load(open(os.path.join(HERE, "adjudication.json")))["items"]
    lab = {r: dict(v) for r, v in lab.items()}
    changes = []
    wl = set()
    for m in mods:
        for rtype, name, attrs, rfile in m.resources:
            if rtype == "aws_security_group" and "cg_whitelist" in json.dumps(attrs.get("ingress", [])):
                wl.add(f"{rfile}::{rtype}.{name}")
    for it in adj:
        if it["dataset"] != ds:
            continue
        for rule in (Rule[it["rule"]],) if it["rule"] != "*" else tuple(lab):
            for k in list(lab.get(rule, {})):
                hit = k == it.get("key") or (it.get("key_contains") == "cg_whitelist" and k in wl)
                if not hit:
                    continue
                if it["action"] == "flip":
                    changes.append({"rule": rule.value, "key": k, "from": lab[rule][k], "to": it["label"], "reason": it["reason"]})
                    lab[rule][k] = it["label"]
                else:
                    changes.append({"rule": rule.value, "key": k, "from": lab[rule][k], "to": None, "reason": it["reason"]})
                    del lab[rule][k]
    return lab, changes


def summarize(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"mean": round(st.mean(xs), 3), "std": round(st.pstdev(xs), 3), "median": round(st.median(xs), 3),
            "p95": round(sorted(xs)[max(0, int(len(xs) * 0.95) - 1)], 3), "n": len(xs)}


def truth_after(rules_before):
    """Ground truth after a run: which original findings still exist (fresh read)."""
    fresh = checks.scan(GuardedSession(reader_identity()))
    still = {f.key for f in fresh}
    return still


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets-dir", default=os.path.join(HERE, "..", "..", "datasets"))
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default=os.path.join(HERE, "..", "results"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    R = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "runs": a.runs, "datasets": {}, "e2": {}, "e3": [], "e4": [], "e5": {}}

    parsed = {}
    for ds, meta in DATASETS.items():
        root = os.path.join(a.datasets_dir, ds, meta["path"]) if meta["path"] else os.path.join(a.datasets_dir, ds)
        lj = os.path.join(a.out, f"checkov_{ds}.json")
        if not os.path.exists(lj):
            print(f"[{ds}] running checkov ...", flush=True)
            labels.run_checkov(root, lj)
        mods = loader.parse_dataset(root, ds)
        parsed[ds] = (root, lj, mods)

        # ---------------- E1 detection accuracy
        with mock_aws():
            t = time.perf_counter()
            rep = loader.deploy(mods)
            t_deploy = time.perf_counter() - t
            lab = labels.load_labels(lj, rep.aux_to_primary)
            lab_adj, changes = adjudicate(ds, lab, mods)
            fs = checks.scan(GuardedSession(reader_identity()))
            pred = predicted(fs)
            raw = labels.score(lab, pred)
            adj = labels.score(lab_adj, pred)
            extra = collections.Counter(f.rule.value for f in fs if f.source_ref and f.rule in (Rule.CLOUDTRAIL_NOT_LOGGING,))
            mism = []
            for rule in labels.SCORED_RULES:
                for k, y in lab.get(rule, {}).items():
                    p = int(k in pred.get(rule, set()))
                    if p != y:
                        mism.append({"rule": rule.value, "key": k, "checkov": y, "detector": p})
        tf_files = sum(1 for m in mods for _ in {r[3] for r in m.resources})
        R["datasets"][ds] = {
            **meta, "commit": git_rev(os.path.join(a.datasets_dir, ds)), "modules": len(mods), "tf_files_with_resources": tf_files,
            "resources_total": sum(len(m.resources) for m in mods), "resources_deployed": len(rep.created),
            "skipped": len(rep.skipped), "deploy_s": round(t_deploy, 2),
            "labels_raw": {r.value: {"pos": sum(v.values()), "neg": len(v) - sum(v.values())} for r, v in lab.items() if v},
            "accuracy_raw": raw, "accuracy_adjudicated": adj, "adjudications": changes, "mismatches_raw": mism,
            "beyond_checkov": dict(extra), "findings_total": len(fs),
        }
        print(f"[{ds}] E1 raw F1={raw['overall']['f1']} adj F1={adj['overall']['f1']} acc={adj['overall']['accuracy']}", flush=True)

    # ---------------- E2 end-to-end remediation, repeated runs
    for ds, (root, lj, mods) in parsed.items():
        per_run, timings = [], collections.defaultdict(list)
        for run in range(a.runs):
            with mock_aws():
                loader.deploy(mods)
                h = SelfHealer(config=Config(verify_backoff_s=0.0))
                t = time.perf_counter()
                res = h.run()
                total = (time.perf_counter() - t) * 1000
                after = checks.scan(GuardedSession(reader_identity()))
                residual = collections.Counter(f.rule.value for f in after)
            c = collections.Counter(o.status.value for o in res["outcomes"])
            auto = [o for o in res["outcomes"] if o.status not in (Status.ESCALATED,)]
            healed_like = sum(1 for o in auto if o.status in (Status.HEALED, Status.ALREADY_RESOLVED))
            per_run.append({"run": run + 1, "findings": len(res["findings"]), "status": dict(c),
                            "auto_fixable": len(auto), "healed_or_resolved": healed_like,
                            "heal_rate": round(healed_like / len(auto), 4) if auto else 1.0,
                            "residual_after": dict(residual), "total_ms": round(total, 1), "detect_ms": round(res["t_detect_ms"], 1)})
            timings["detect"].append(res["t_detect_ms"])
            for o in res["outcomes"]:
                if o.status == Status.HEALED:
                    timings["decide"].append(o.t_decide_ms)
                    timings["fix"].append(o.t_fix_ms)
                    timings["verify"].append(o.t_verify_ms)
                    timings[f"mttr:{o.finding.rule.value}"].append(o.t_decide_ms + o.t_fix_ms + o.t_verify_ms)
        by_rule = collections.defaultdict(lambda: collections.Counter())
        for o in res["outcomes"]:
            by_rule[o.finding.rule.value][o.status.value] += 1
        R["e2"][ds] = {"runs": per_run, "timings_ms": {k: summarize(v) for k, v in timings.items()},
                       "by_rule_last_run": {k: dict(v) for k, v in by_rule.items()},
                       "heal_rate_mean": round(st.mean(r["heal_rate"] for r in per_run), 4)}
        print(f"[{ds}] E2 heal rate {R['e2'][ds]['heal_rate_mean']} findings {per_run[0]['findings']} status {per_run[-1]['status']}", flush=True)

    # ---------------- E3 AI selector robustness (all datasets pooled)
    configs = {
        "guardrail+verify": Config(guardrail=True, verify=True, verify_backoff_s=0.0),
        "guardrail+fallback+verify": Config(guardrail=True, fallback_to_rules=True, verify=True, verify_backoff_s=0.0),
        "no-guardrail+verify": Config(guardrail=False, verify=True, verify_backoff_s=0.0, max_fix_attempts=1),
        "no-guardrail,no-verify": Config(guardrail=False, verify=False, verify_backoff_s=0.0),
    }
    for err in (0.0, 0.1, 0.2, 0.3, 0.5):
        for cname, cfg in configs.items():
            agg = collections.Counter()
            for seed in range(a.runs):
                for ds, (root, lj, mods) in parsed.items():
                    with mock_aws():
                        loader.deploy(mods)
                        h = SelfHealer(selector=NoisySelector(err, seed=seed * 7 + len(ds)), config=cfg)
                        res = h.run()
                        still = {f.key for f in checks.scan(GuardedSession(reader_identity()))}
                    for o in res["outcomes"]:
                        if o.status == Status.ESCALATED:
                            continue
                        agg["n"] += 1
                        truly = o.finding.key not in still
                        agg["truly_fixed"] += truly
                        claimed = o.status in (Status.HEALED, Status.ALREADY_RESOLVED)
                        agg["claimed_healed"] += claimed
                        agg["false_heal_claims"] += claimed and not truly
                        agg["blocked"] += o.status == Status.BLOCKED
                        wrong = o.tool is not None and o.tool in TOOLS and o.finding.rule not in (TOOLS[o.tool].fixes,) \
                            and not (o.finding.rule == Rule.CLOUDTRAIL_MISSING and o.tool == "enable_cloudtrail") and o.status != Status.BLOCKED
                        agg["wrong_tool_executed"] += wrong
                        agg["invented_tool"] += (o.tool is not None and o.tool not in TOOLS)
            n = agg["n"] or 1
            R["e3"].append({"error_rate": err, "config": cname, "n": agg["n"],
                            "true_fix_rate": round(agg["truly_fixed"] / n, 4),
                            "false_heal_claim_rate": round(agg["false_heal_claims"] / n, 4),
                            "wrong_tool_executed_rate": round(agg["wrong_tool_executed"] / n, 4),
                            "blocked_rate": round(agg["blocked"] / n, 4), "invented_tool": agg["invented_tool"]})
        print(f"E3 err={err} done", flush=True)

    # ---------------- E4 fault injection (all datasets pooled)
    scenarios = [
        ("baseline", 0, 0.0, 0.0),
        ("stale reads k=2", 2, 0.0, 0.0),
        ("stale reads k=6", 6, 0.0, 0.0),
        ("partial fix p=0.3", 0, 0.3, 0.0),
        ("transient error p=0.2", 0, 0.0, 0.2),
        ("all faults", 2, 0.3, 0.2),
    ]
    for name, k, pp, ep in scenarios:
        for verify in (True, False):
            agg = collections.Counter()
            for seed in range(a.runs):
                for ds, (root, lj, mods) in parsed.items():
                    with mock_aws():
                        loader.deploy(mods)
                        cfg = Config(verify=verify, verify_backoff_s=0.0, verify_retries=4, max_fix_attempts=2 if verify else 1)
                        h = SelfHealer(config=cfg, tool_wrapper=FaultyTools(pp, ep, seed=seed) if (pp or ep) else None,
                                       recheck_fn=StaleReads(k) if k else checks.recheck)
                        res = h.run()
                        still = {f.key for f in checks.scan(GuardedSession(reader_identity()))}
                    for o in res["outcomes"]:
                        if o.status == Status.ESCALATED:
                            continue
                        agg["n"] += 1
                        truly = o.finding.key not in still
                        claimed = o.status in (Status.HEALED, Status.ALREADY_RESOLVED)
                        agg["truly"] += truly
                        agg["false_claim"] += claimed and not truly
                        agg["missed_true"] += (not claimed) and truly
                        agg["attempts"] += o.attempts
            n = agg["n"] or 1
            R["e4"].append({"scenario": name, "verification": verify, "n": agg["n"],
                            "true_fix_rate": round(agg["truly"] / n, 4),
                            "false_heal_claim_rate": round(agg["false_claim"] / n, 4),
                            "unconfirmed_but_fixed_rate": round(agg["missed_true"] / n, 4),
                            "avg_attempts": round(agg["attempts"] / n, 3)})
        print(f"E4 {name} done", flush=True)

    # ---------------- E5 least privilege
    dangerous = [("s3", "delete_bucket", {"Bucket": "x"}), ("ec2", "terminate_instances", {"InstanceIds": ["i-1"]}),
                 ("iam", "create_access_key", {"UserName": "x"}), ("cloudtrail", "delete_trail", {"Name": "x"}),
                 ("cloudtrail", "stop_logging", {"Name": "x"}), ("s3", "put_bucket_policy", {"Bucket": "x", "Policy": "{}"}),
                 ("ec2", "authorize_security_group_egress", {"GroupId": "sg-1", "IpPermissions": []}),
                 ("iam", "attach_user_policy", {"UserName": "x", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
                 ("s3", "delete_public_access_block", {"Bucket": "x"}), ("ec2", "modify_instance_attribute", {"InstanceId": "i-1"})]
    blocked = 0
    with mock_aws():
        g = GuardedSession(remediator_identity(all_tool_actions()))
        for svc, op, kw in dangerous:
            try:
                getattr(g.client(svc), op)(**kw)
            except PermissionDenied:
                blocked += 1
            except Exception:
                pass
        rdr = GuardedSession(reader_identity())
        writes_blocked = 0
        for t in TOOLS.values():
            for act in t.actions:
                if not rdr.identity.permits(act):
                    writes_blocked += 1
    R["e5"] = {"out_of_policy_calls": len(dangerous), "blocked": blocked,
               "verifier_write_actions_denied": writes_blocked,
               "verifier_write_actions_total": sum(len(t.actions) for t in TOOLS.values()),
               "remediator_write_actions": sorted(a for a in all_tool_actions())}
    print("E5", R["e5"]["blocked"], "/", len(dangerous))

    with open(os.path.join(a.out, "results.json"), "w") as f:
        json.dump(R, f, indent=2)
    print("wrote", os.path.join(a.out, "results.json"))


if __name__ == "__main__":
    main()
