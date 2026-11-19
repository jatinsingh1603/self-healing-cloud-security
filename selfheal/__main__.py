"""Command line interface.

  python -m selfheal demo                 # the 3 deck scenarios + extras, on an emulated account
  python -m selfheal demo --approve       # also apply the HIGH-risk IAM fix (human approval given)
  python -m selfheal dataset sadcloud --path ../datasets/sadcloud
  python -m selfheal scan --live          # read-only scan of a REAL AWS account (uses your AWS credentials)
  python -m selfheal heal --live --yes    # heal a REAL account (least-privilege tools only)
  python -m selfheal policy               # print the least-privilege IAM policies
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .model import Status

C = {"HEALED": "\033[32m", "ALREADY_RESOLVED": "\033[36m", "ESCALATED": "\033[33m", "BLOCKED": "\033[35m",
     "NOT_HEALED": "\033[31m", "ERROR": "\033[31m", "end": "\033[0m", "dim": "\033[2m", "b": "\033[1m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


def _print_findings(fs):
    print(f"{C['b']}DETECT{C['end']}  {len(fs)} finding(s)")
    for f in fs:
        print(f"  [{f.severity:8}] {f.rule.value:30} {f.resource_id}")


def _event(kind, kw):
    if kind == "decide":
        print(f"  {C['dim']}decide{C['end']}  {kw['finding']['rule']:30} -> {kw['tool']}")
    elif kind == "fix":
        print(f"  {C['dim']}fix   {C['end']}  {kw['tool']:30}    {kw['detail']}")
    elif kind == "verify":
        s = kw["status"]
        print(f"  {C['dim']}verify{C['end']}  {kw['finding']['rule']:30} {C.get(s, '')}{s}{C['end']}")


def _summary(res):
    from collections import Counter
    c = Counter(o.status.value for o in res["outcomes"])
    print(f"\n{C['b']}RESULT{C['end']}  " + "  ".join(f"{C.get(k, '')}{k}={v}{C['end']}" for k, v in c.items()))
    for o in res["outcomes"]:
        if o.status in (Status.ESCALATED, Status.BLOCKED, Status.NOT_HEALED):
            print(f"  {C.get(o.status.value, '')}{o.status.value}{C['end']} {o.finding.rule.value} {o.finding.resource_id}: {o.detail}")


def _mock():
    os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="us-east-1")
    from moto import mock_aws
    return mock_aws()


def _selector(name):
    from .decide import LLMSelector, RuleSelector
    return LLMSelector() if name == "llm" else RuleSelector()


def cmd_demo(a):
    from .engine import Config, SelfHealer
    from .scenarios import seed_controlled, seed_extra
    with _mock():
        seed_controlled()
        if not a.only_three:
            seed_extra()
        h = SelfHealer(selector=_selector(a.selector), config=Config(approve_high_risk=a.approve),
                       audit_path=a.audit, on_event=_event)
        fs, ms = h.detect()
        _print_findings(fs)
        print(f"  {C['dim']}({ms:.0f} ms){C['end']}\n\n{C['b']}DECIDE > FIX > VERIFY{C['end']}")
        t = time.perf_counter()
        res = h.run()
        _summary(res)
        print(f"\n{C['b']}RE-SCAN{C['end']}  {len(h.detect()[0])} finding(s) left  ({(time.perf_counter() - t) * 1000:.0f} ms total)")
        if a.json:
            json.dump([o.to_dict() for o in res["outcomes"]], open(a.json, "w"), indent=2)


def cmd_dataset(a):
    from . import loader
    from .engine import Config, SelfHealer
    with _mock():
        mods = loader.parse_dataset(a.path, a.name)
        rep = loader.deploy(mods)
        print(f"deployed {len(rep.created)} resources from {len(mods)} modules of {a.name}")
        h = SelfHealer(config=Config(approve_high_risk=a.approve), audit_path=a.audit, on_event=_event if a.verbose else None)
        fs, _ = h.detect()
        _print_findings(fs)
        res = h.run()
        _summary(res)
        print(f"re-scan: {len(h.detect()[0])} finding(s) left")


def cmd_live(a, heal: bool):
    from .engine import Config, SelfHealer
    h = SelfHealer(region=a.region, selector=_selector(a.selector),
                   config=Config(approve_high_risk=a.approve, dry_run=not (heal and a.yes)), audit_path=a.audit, on_event=_event)
    fs, _ = h.detect()
    _print_findings(fs)
    if heal:
        if not a.yes:
            print("\n(dry run: add --yes to apply fixes)")
        _summary(h.run())


def cmd_policy(_):
    from .guard import reader_identity, remediator_identity
    from .tools import all_tool_actions
    print("# SelfHealRemediator\n" + json.dumps(remediator_identity(all_tool_actions()).policy_document(), indent=2))
    print("# SelfHealReader (verifier)\n" + json.dumps(reader_identity().policy_document(), indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="selfheal", description="Self-Healing Cloud Security")
    sp = ap.add_subparsers(dest="cmd", required=True)
    d = sp.add_parser("demo"); d.add_argument("--approve", action="store_true"); d.add_argument("--only-three", action="store_true")
    d.add_argument("--selector", choices=["rule", "llm"], default="rule"); d.add_argument("--audit", default="audit.jsonl"); d.add_argument("--json")
    ds = sp.add_parser("dataset"); ds.add_argument("name"); ds.add_argument("--path", required=True)
    ds.add_argument("--approve", action="store_true"); ds.add_argument("--verbose", action="store_true"); ds.add_argument("--audit")
    for n in ("scan", "heal"):
        x = sp.add_parser(n); x.add_argument("--live", action="store_true", required=True); x.add_argument("--region", default="us-east-1")
        x.add_argument("--selector", choices=["rule", "llm"], default="rule"); x.add_argument("--approve", action="store_true")
        x.add_argument("--yes", action="store_true"); x.add_argument("--audit", default="audit.jsonl")
    sp.add_parser("policy")
    a = ap.parse_args(argv)
    if a.cmd == "demo":
        cmd_demo(a)
    elif a.cmd == "dataset":
        cmd_dataset(a)
    elif a.cmd in ("scan", "heal"):
        cmd_live(a, a.cmd == "heal")
    else:
        cmd_policy(a)


if __name__ == "__main__":
    main()
