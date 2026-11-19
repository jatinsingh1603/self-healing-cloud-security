"""Build the final presentation (PDF + per-slide PNG) from results/results.json.

python deck/build_deck.py <site_url> <repo_url>
"""
import asyncio
import base64
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
R = json.load(open(os.path.join(ROOT, "results", "results.json")))
FIG = os.path.join(ROOT, "results", "figures")
SITE = sys.argv[1] if len(sys.argv) > 1 else "https://jatinsingh1603.github.io/self-healing-cloud-security/"
REPO = sys.argv[2] if len(sys.argv) > 2 else "https://github.com/jatinsingh1603/self-healing-cloud-security"
DS = list(R["datasets"])


def img(name):
    return "data:image/png;base64," + base64.b64encode(open(os.path.join(FIG, name), "rb").read()).decode()


def pool(kind):
    t = dict(tp=0, fp=0, fn=0, tn=0)
    for d in DS:
        o = R["datasets"][d][f"accuracy_{kind}"]["overall"]
        for k in t:
            t[k] += o[k]
    p = t["tp"] / (t["tp"] + t["fp"]); r = t["tp"] / (t["tp"] + t["fn"])
    return {**t, "p": p, "r": r, "f1": 2 * p * r / (p + r), "acc": (t["tp"] + t["tn"]) / sum(t.values()), "n": sum(t.values())}


RAW, ADJ = pool("raw"), pool("adjudicated")
FIND = sum(R["e2"][d]["runs"][0]["findings"] for d in DS)
ESC = sum(R["e2"][d]["runs"][0]["status"].get("ESCALATED", 0) for d in DS)
HEAL = sum(R["e2"][d]["heal_rate_mean"] for d in DS) / len(DS)
e4 = {(x["scenario"], x["verification"]): x for x in R["e4"]}
e3 = {(x["config"], x["error_rate"]): x for x in R["e3"]}
ADJN = sum(len(R["datasets"][d]["adjudications"]) for d in DS)
FLIPS = sum(1 for d in DS for a in R["datasets"][d]["adjudications"] if a["to"] is not None)
EXCL = ADJN - FLIPS
pc = lambda x: f"{x * 100:.1f}%".replace(".0%", "%")

CSS = """
@page{size:1920px 1080px;margin:0}
*{box-sizing:border-box}
body{margin:0;font-family:Inter,system-ui,sans-serif;color:#111827;-webkit-font-smoothing:antialiased}
.s{width:1920px;height:1080px;padding:96px 120px 90px;position:relative;page-break-after:always;overflow:hidden;background:#fff}
.s .ft{position:absolute;left:120px;right:120px;bottom:44px;display:flex;justify-content:space-between;font-size:17px;color:#8b95a3;border-top:1px solid #e6e8ec;padding-top:16px}
.ey{font-size:20px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:#1f4fd1;margin-bottom:14px}
h1{font-size:96px;line-height:1.02;letter-spacing:-.03em;margin:0 0 28px;font-weight:600}
h2{font-size:56px;line-height:1.1;letter-spacing:-.02em;margin:0 0 36px;font-weight:600}
h3{font-size:32px;margin:0 0 14px;font-weight:600}
p,li{font-size:30px;line-height:1.5;color:#374151}
ul{margin:0;padding-left:30px} li{margin-bottom:18px}
.mut{color:#5f6b7a}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:56px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:40px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border:1px solid #e6e8ec;border-radius:10px;overflow:hidden}
.box{border:1px solid #e6e8ec;border-radius:10px;padding:30px 32px;background:#fff}
.box.tint{background:#f6f8fc}
.k{padding:30px 32px;border-right:1px solid #e6e8ec} .k:last-child{border-right:0}
.k .v{font-size:60px;font-weight:600;letter-spacing:-.02em} .k .l{font-size:21px;color:#5f6b7a;line-height:1.4;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:25px}
th{text-align:left;font-size:16px;letter-spacing:.06em;text-transform:uppercase;color:#5f6b7a;padding:12px 14px;border-bottom:2px solid #d5d9e0;font-weight:600}
td{padding:13px 14px;border-bottom:1px solid #e6e8ec;color:#1f2937;vertical-align:top}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.86em}
.fig{width:100%;border:1px solid #e6e8ec;border-radius:10px;padding:16px;background:#fff}
.tick{color:#2e8b57;font-weight:700} .cross{color:#b9c0ca}
.step{border-top:4px solid #1f4fd1;padding-top:20px}
.step .n{font-size:18px;font-weight:600;color:#1f4fd1}
.tag{display:inline-block;font-size:17px;font-weight:600;padding:4px 12px;border-radius:6px;border:1px solid #d5d9e0;color:#5f6b7a;margin:0 8px 8px 0}
.callout{border-left:5px solid #1f4fd1;background:#f6f8fc;padding:22px 30px;border-radius:0 10px 10px 0}
.big{font-size:34px;line-height:1.35;color:#111827}
"""

TEAM = [("Jatin", "23CSU141"), ("Deepanshu", "23CSU091"), ("Yana", "23CSU395"), ("Ishant", "23CSU130"), ("Indresh", "23CSU128")]
slides = []


def S(title, body, ey=""):
    slides.append((title, ey, body))


# 0 ----------------------------------------------------------------- title
slides.append(("__title__", "", f"""
<div style="display:flex;flex-direction:column;height:100%">
 <div class="ey">CSL-384 Cloud Security Essentials - Final Project Evaluation - 20 November 2026</div>
 <h1 style="margin-top:110px">Self-Healing<br>Cloud Security</h1>
 <p class="big" style="max-width:1300px;color:#374151">AI-driven detection, remediation and independent verification of AWS misconfigurations, evaluated on three public datasets.</p>
 <div style="margin-top:auto;display:flex;gap:70px">
  <div><div class="ey" style="color:#5f6b7a">Team</div><table style="width:auto;font-size:26px">{''.join(f'<tr><td style="padding:6px 50px 6px 0;border:0"><b>{n}</b></td><td style="padding:6px 0;border:0" class="mut">{r}</td></tr>' for n, r in TEAM)}</table></div>
  <div><div class="ey" style="color:#5f6b7a">Faculty</div><p style="margin:6px 0">Arun Kumar Jindal</p><p class="mut" style="margin:0">The NorthCap University, Gurugram</p></div>
  <div><div class="ey" style="color:#5f6b7a">Live demo</div><p style="margin:6px 0;font-size:22px">{SITE.replace('https://', '')}</p><p class="mut" style="margin:0;font-size:22px">{REPO.replace('https://', '')}</p></div>
 </div>
</div>"""))

# 1 ----------------------------------------------------------------- problem
S("Problem statement and motivation", f"""
<div class="g2">
 <div>
  <h3>Cloud configuration drift</h3>
  <p>Cloud resources change every day. One click can make a bucket public, open SSH to the internet or switch off audit logging, and the exposure lasts until someone notices.</p>
  <ul><li><b>Public S3 access</b> exposes stored data</li><li><b>Unrestricted SSH / RDP</b> invites brute force and remote access</li><li><b>Disabled CloudTrail</b> removes the audit trail an investigation needs</li></ul>
 </div>
 <div>
  <h3>Why existing practice falls short</h3>
  <ul><li>Scanners report problems; a person still has to fix each one, so the mean time to remediate stays high.</li>
  <li>Auto-remediation scripts are trusted blindly: an API that returns 200 OK is not proof the resource is safe.</li>
  <li>Letting an AI agent touch production raises a new question: what stops a wrong or invented action?</li></ul>
  <div class="callout" style="margin-top:26px"><p class="big" style="margin:0"><b>Objective:</b> close the loop from finding to <i>verified</i> fix, with every action bounded by approved tools and least privilege.</p></div>
 </div>
</div>""", "01 Problem")

# 2 ----------------------------------------------------------------- related work
rw = [("AWS Config + SSM remediation", 1, 1, 0, 0, 0), ("AWS Security Hub ASR", 1, 1, 0, 0, 0), ("Checkov (IaC static analysis)", 1, 0, 0, 0, 0),
      ("Cloud Custodian", 1, 1, 0, 1, 0), ("Prowler / ScoutSuite", 1, 0, 0, 0, 0), ("<b>This project</b>", 1, 1, 1, 1, 1)]
mark = lambda b: '<span class="tick">&#10003;</span>' if b else '<span class="cross">-</span>'
S("Related work", f"""
<table><thead><tr><th>System</th><th>Detects</th><th>Auto-fixes</th><th>AI chooses the fix</th><th>Bounded tool set + least privilege</th><th>Independent re-check of every fix</th></tr></thead><tbody>
{''.join(f'<tr><td>{n}</td>' + ''.join(f'<td>{mark(x)}</td>' for x in v) + '</tr>' for n, *v in rw)}
</tbody></table>
<p class="mut" style="margin-top:30px;font-size:22px">[1] AWS Config remediation with SSM Automation. [2] Automated Security Response on AWS. [3] Checkov, Bridgecrew / Palo Alto Networks. [4] Cloud Custodian, Cloud Native Computing Foundation. [5] Prowler, ScoutSuite (NCC Group). Benchmarks: CIS AWS Foundations Benchmark.</p>
<p style="margin-top:12px">Gap we address: existing tools either only report, or fix without proving the fix took effect and without guardrails for an AI decision maker.</p>""", "02 Related work")

# 3 ----------------------------------------------------------------- methodology architecture
S("Methodology: a closed control loop", f"""
<div class="g4" style="margin-bottom:40px">
 <div class="k step" style="border-top:4px solid #1f4fd1"><div class="n">01 DETECT</div><h3 style="margin-top:8px">Read-only scan</h3><p style="font-size:22px">SelfHealReader identity lists S3, security groups, CloudTrail and IAM and evaluates 10 CIS-aligned rules.</p></div>
 <div class="k step" style="border-top:4px solid #1f4fd1"><div class="n">02 DECIDE</div><h3 style="margin-top:8px">AI picks one tool</h3><p style="font-size:22px">An LLM agent (or fixed rules) selects from the approved registry. A guardrail rejects any tool not approved for that rule.</p></div>
 <div class="k step" style="border-top:4px solid #1f4fd1"><div class="n">03 FIX</div><h3 style="margin-top:8px">Least-privilege apply</h3><p style="font-size:22px">SelfHealRemediator may call only the {len(R['e5']['remediator_write_actions'])} actions the tools need. HIGH-risk tools wait for a human.</p></div>
 <div class="k step" style="border-top:4px solid #1f4fd1"><div class="n">04 VERIFY</div><h3 style="margin-top:8px">Independent re-check</h3><p style="font-size:22px">A separate read-only identity re-reads the resource with backoff. One retry, then HEALED or NOT HEALED.</p></div>
</div>
<div class="g2">
 <div class="box tint"><h3>Three identities, separated duties</h3><p style="font-size:23px;margin:0">The component that judges "healed" cannot modify what it judges; the component that modifies cannot exceed its policy. Every outcome and every API call is written to an audit log.</p></div>
 <div class="box tint"><h3>Implementation</h3><p style="font-size:23px;margin:0">Python 3, boto3. Runs against a live AWS account or the moto AWS emulator (same API calls). Pluggable decision maker: Anthropic, OpenAI-compatible or an n8n agent webhook, with fixed rules as safe fallback.</p></div>
</div>""", "03 Methodology")

# 4 ----------------------------------------------------------------- rules & tools
tools = [("S3 public access", "fix_s3_public_access", "LOW", "PutBucketPublicAccessBlock, PutBucketAcl"),
         ("S3 versioning off", "enable_s3_versioning", "LOW", "PutBucketVersioning"),
         ("S3 no KMS encryption", "enable_s3_kms_encryption", "LOW", "PutEncryptionConfiguration"),
         ("SG open SSH / RDP / all ports", "fix_open_ssh / rdp / all_ingress", "MEDIUM", "RevokeSecurityGroupIngress"),
         ("CloudTrail off / missing", "enable_cloudtrail", "LOW", "StartLogging, CreateTrail"),
         ("CloudTrail single-region / no validation", "set_cloudtrail_multiregion, enable_..._log_validation", "LOW", "UpdateTrail"),
         ("IAM policy with Action *", "quarantine_admin_policy", "HIGH", "CreatePolicyVersion (needs approval)")]
S("Methodology: rules, approved tools and permissions", f"""
<table><thead><tr><th>Misconfiguration (CIS AWS)</th><th>Approved tool</th><th>Risk</th><th>Only IAM actions granted</th></tr></thead><tbody>
{''.join(f'<tr><td>{a}</td><td class="mono">{b}</td><td><b style="color:{"#2e8b57" if c=="LOW" else "#c58a1b" if c=="MEDIUM" else "#c0392b"}">{c}</b></td><td class="mono">{d}</td></tr>' for a, b, c, d in tools)}
</tbody></table>
<p style="margin-top:28px">Fixes are surgical: revoking SSH from 0.0.0.0/0 keeps HTTPS open; quarantining an admin policy keeps the old version for rollback.</p>""", "03 Methodology")

# 5 ----------------------------------------------------------------- datasets
rowsd = "".join(f"""<tr><td><b>{d}</b><div class="mut" style="font-size:18px">{R['datasets'][d]['repo'].replace('https://github.com/', 'github.com/')}</div></td><td>{R['datasets'][d]['by']}</td>
<td class="n">{R['datasets'][d]['resources_total']}</td><td class="n">{R['datasets'][d]['resources_deployed']}</td><td class="n">{R['datasets'][d]['accuracy_raw']['overall']['n']}</td><td class="mono">{R['datasets'][d]['commit']}</td></tr>""" for d in DS)
S("Experiments: three public datasets", f"""
<table><thead><tr><th>Dataset</th><th>Published by</th><th class="n">Terraform resources</th><th class="n">In-scope deployed</th><th class="n">Labelled pairs</th><th>Commit</th></tr></thead><tbody>{rowsd}</tbody></table>
<div class="g2" style="margin-top:40px">
 <div><h3>Pipeline</h3><p style="font-size:23px">Parse each dataset's Terraform (variables, locals, conditionals) and create every in-scope resource through boto3 in an emulated AWS account, exactly as <span class="mono">terraform apply</span> would. Then run the full loop on the deployed state.</p></div>
 <div><h3>Ground truth</h3><p style="font-size:23px">Checkov, the open-source scanner, labels the same CIS properties on the source code. Each (resource, rule) pair is scored: {RAW['n']} labels in total. Every disagreement was then reviewed by hand and documented.</p></div>
</div>""", "04 Experiments")

# 6 ----------------------------------------------------------------- experiment design
S("Experiments: what we measured", f"""
<div class="g2" style="row-gap:30px">
 <div class="box"><h3>E1 Detection accuracy</h3><p style="font-size:23px;margin:0">Precision, recall, F1 and accuracy vs Checkov labels, raw and after adjudication, per dataset and per rule.</p></div>
 <div class="box"><h3>E2 End-to-end remediation</h3><p style="font-size:23px;margin:0">Verified heal rate, outcome per finding and detect / decide / fix / verify time, over {R['runs']} repeated runs.</p></div>
 <div class="box"><h3>E3 AI robustness</h3><p style="font-size:23px;margin:0">Simulated LLM that picks a wrong or invented tool 0-50% of the time, with guardrail and verification switched on and off.</p></div>
 <div class="box"><h3>E4 Cloud faults</h3><p style="font-size:23px;margin:0">Injected stale reads, partial fixes (200 OK, change half applied) and throttling errors, with and without verification.</p></div>
 <div class="box"><h3>E5 Least privilege</h3><p style="font-size:23px;margin:0">Dangerous calls (DeleteBucket, TerminateInstances, CreateAccessKey, StopLogging...) attempted through the remediator.</p></div>
 <div class="box tint"><h3>Truth after every run</h3><p style="font-size:23px;margin:0">After each run a fresh scan decides what is really fixed, so a "HEALED" claim can be checked rather than trusted.</p></div>
</div>""", "04 Experiments")

# 7 ----------------------------------------------------------------- E1
S("Results: detection accuracy on public data", f"""
<div class="g4" style="margin-bottom:34px">
 <div class="k"><div class="v">{pc(RAW['acc'])}</div><div class="l">accuracy vs raw Checkov labels<br>(n = {RAW['n']})</div></div>
 <div class="k"><div class="v">{RAW['p']:.3f}</div><div class="l">precision (raw)</div></div>
 <div class="k"><div class="v">{RAW['r']:.3f}</div><div class="l">recall (raw)</div></div>
 <div class="k"><div class="v">{RAW['f1']:.3f}</div><div class="l">F1 raw; {ADJ['f1']:.3f} after reviewing all {ADJN} disagreements</div></div>
</div>
<div class="g2"><img class="fig" src="{img('e1_accuracy.png')}"><img class="fig" src="{img('e1_per_rule.png')}"></div>""", "05 Results")

# 8 ----------------------------------------------------------------- adjudication
adj_rows = []
seen = set()
for d in DS:
    for a in R["datasets"][d]["adjudications"]:
        k = (d, a["reason"][:40])
        if k in seen:
            continue
        seen.add(k)
        n = sum(1 for b in R["datasets"][d]["adjudications"] if b["reason"] == a["reason"])
        adj_rows.append((d, n, a["to"], a["reason"]))
S("Results: every disagreement, reviewed", f"""
<table style="font-size:21px"><thead><tr><th>Dataset</th><th class="n">Labels</th><th>Decision</th><th>Reason</th></tr></thead><tbody>
{''.join(f'<tr><td>{d}</td><td class="n">{n}</td><td style="white-space:nowrap">{"excluded" if to is None else ("Checkov FP" if to == 0 else "Checkov FN")}</td><td style="font-size:20px;padding:9px 14px">{r}</td></tr>' for d, n, to, r in adj_rows)}
</tbody></table>
<p style="margin-top:20px;font-size:25px">{FLIPS} labels were Checkov errors (ICMP treated as SSH, protocol -1 not treated as all ports, an unresolved conditional) and {EXCL} depended on an operator-supplied IP list. We report both raw and adjudicated numbers.</p>""", "05 Results")

# 9 ----------------------------------------------------------------- E2
S("Results: remediation and timing", f"""
<div class="g4" style="margin-bottom:34px">
 <div class="k"><div class="v">{FIND}</div><div class="l">findings detected across the 3 datasets per run</div></div>
 <div class="k"><div class="v">{pc(HEAL)}</div><div class="l">of auto-fixable findings healed and independently verified</div></div>
 <div class="k"><div class="v">{ESC}</div><div class="l">HIGH-risk IAM findings escalated to a human, never auto-applied</div></div>
 <div class="k"><div class="v">{sum((R['e2'][d]['timings_ms'].get('fix') or {{}}).get('mean', 0) + (R['e2'][d]['timings_ms'].get('verify') or {{}}).get('mean', 0) for d in DS) / len(DS):.0f} ms</div><div class="l">mean fix + verify per finding (emulated AWS)</div></div>
</div>
<div class="g2"><img class="fig" src="{img('e2_outcomes.png')}"><img class="fig" src="{img('e2_timing.png')}"></div>""", "05 Results")

# 10 ---------------------------------------------------------------- E3
S("Results: when the AI picks the wrong tool", f"""
<img class="fig" src="{img('e3_robustness.png')}" style="width:1180px;display:block;margin:-14px auto 16px">
<div class="g3">
 <div><h3>No guardrail</h3><p style="font-size:25px">At 30% AI error, {pc(e3[('no-guardrail+verify', 0.3)]['wrong_tool_executed_rate'])} of findings had a wrong tool executed on a real resource.</p></div>
 <div><h3>Guardrail</h3><p style="font-size:25px">Wrong tools executed: 0% at every error rate. Bad choices are blocked before any API call.</p></div>
 <div><h3>Guardrail + safe fallback</h3><p style="font-size:25px">True fix rate stays at {pc(e3[('guardrail+fallback+verify', 0.5)]['true_fix_rate'])} even when the AI is wrong half the time.</p></div>
</div>""", "05 Results")

# 11 ---------------------------------------------------------------- E4 + E5
af_n, af_v = e4[("all faults", False)], e4[("all faults", True)]
S("Results: cloud faults and least privilege", f"""
<div class="g2" style="grid-template-columns:1.35fr 1fr;align-items:start">
 <img class="fig" src="{img('e4_faults.png')}">
 <div>
  <div class="box" style="margin-bottom:22px"><h3>Verification catches silent failures</h3><p style="font-size:23px;margin:0">With all faults injected, <b>{pc(af_n['false_heal_claim_rate'])}</b> of findings were reported healed but were not, without verification. With independent re-check and one retry: <b>{pc(af_v['false_heal_claim_rate'])}</b>, and the true fix rate rose from {pc(af_n['true_fix_rate'])} to {pc(af_v['true_fix_rate'])}.</p></div>
  <div class="box"><h3>Least privilege (E5)</h3><p style="font-size:23px;margin:0"><b>{R['e5']['blocked']}/{R['e5']['out_of_policy_calls']}</b> dangerous out-of-policy API calls blocked. <b>{R['e5']['verifier_write_actions_denied']}/{R['e5']['verifier_write_actions_total']}</b> write actions denied to the verifier.</p></div>
 </div>
</div>""", "05 Results")

# 12 ---------------------------------------------------------------- observations
S("Our observations", f"""
<ul style="columns:2;column-gap:70px">
<li><b>The reference scanner is not ground truth.</b> {FLIPS} Checkov labels were wrong on inspection, in both directions. Runtime checks on deployed state avoid static-analysis blind spots such as ICMP rules and protocol -1.</li>
<li><b>Verification found our own bugs.</b> Checking "healed" against a fresh scan exposed a verifier that trusted an API filter, and a fix that created a non-compliant log bucket. Both were fixed before the final runs.</li>
<li><b>An AI selector needs a guardrail more than accuracy.</b> Even a 10% error rate executed wrong tools without one; with it, wrong executions were zero.</li>
<li><b>200 OK is not healed.</b> Partial fixes and throttling silently left {pc(af_n['false_heal_claim_rate'])} of findings open without re-checks.</li>
<li><b>Ordering matters.</b> Fixing the broadest finding first (all-ports) resolves narrower ones on the same group, recorded as ALREADY_RESOLVED.</li>
<li><b>Eventual consistency costs retries, not correctness.</b> Six stale reads in a row pushed fixes to a second attempt (1.9 on average) but every one still ended verified.</li><li><b>Limits:</b> experiments ran on the moto emulator, not a production account, and the AI errors were simulated so the rate could be controlled.</li>
</ul>""", "06 Observations")

# 13 ---------------------------------------------------------------- conclusion
S("Conclusion", f"""
<p class="big" style="font-size:52px;line-height:1.2;letter-spacing:-.02em;margin:0 0 50px;max-width:1500px">Self-healing is safe only when every fix is bounded before it runs and verified after it runs.</p>
<div class="g3">
 <div class="step"><div class="n">ACCURATE</div><p>{pc(RAW['acc'])} accuracy and {RAW['f1']:.2f} F1 against raw labels on {RAW['n']} labelled pairs from 3 public datasets.</p></div>
 <div class="step"><div class="n">EFFECTIVE</div><p>{pc(HEAL)} of auto-fixable findings healed and independently verified in every one of {R['runs']} repeated runs.</p></div>
 <div class="step"><div class="n">SAFE</div><p>Zero wrong tools executed under a faulty AI, {R['e5']['blocked']}/{R['e5']['out_of_policy_calls']} dangerous calls blocked, HIGH-risk changes left to a human.</p></div>
</div>""", "07 Conclusion")

# 14 ---------------------------------------------------------------- future work
S("Future work", """
<div class="g3">
 <div class="step"><div class="n">NEXT</div><h3 style="margin-top:8px">Live account pilot</h3><p style="font-size:23px">Run the same code (already supports <span class="mono">--live</span>) on a sandbox AWS account with EventBridge triggers for near real-time healing.</p></div>
 <div class="step"><div class="n">THEN</div><h3 style="margin-top:8px">Broader coverage</h3><p style="font-size:23px">RDS public access, EBS encryption, IMDSv2, KMS key rotation; Azure and GCP via the same detect / tool / verify contract.</p></div>
 <div class="step"><div class="n">FURTHER</div><h3 style="margin-top:8px">Smarter AI, same guardrails</h3><p style="font-size:23px">Benchmark real LLMs on tool choice, add approval workflows (Slack / n8n) and change windows, and a second independent reference scanner (Prowler) for labels.</p></div>
</div>""", "08 Future work")

# 15 ---------------------------------------------------------------- demo / links
S("Demo and submission", f"""
<div class="g2">
 <div><h3>Live demo (hosted)</h3><p class="big" style="margin:0 0 30px"><a style="color:#1f4fd1;text-decoration:none" href="{SITE}">{SITE.replace('https://', '')}</a></p>
  <h3>Source code</h3><p class="big" style="margin:0 0 30px"><a style="color:#1f4fd1;text-decoration:none" href="{REPO}">{REPO.replace('https://', '')}</a></p>
  <p style="font-size:23px">The site runs the loop interactively, replays the recorded runs on all three datasets and shows every experiment result.</p></div>
 <div class="box tint"><h3>Run it</h3><pre class="mono" style="font-size:21px;line-height:1.6;margin:0;white-space:pre-wrap">pip install -r requirements.txt
python -m selfheal demo
python -m selfheal demo --approve
python -m pytest -q
bash experiments/get_datasets.sh
python experiments/run_all.py</pre></div>
</div>""", "Demo")


def render_html():
    out = []
    n = len(slides)
    for i, (title, ey, body) in enumerate(slides):
        head = "" if title == "__title__" else f'<div class="ey">{ey}</div><h2>{title}</h2>'
        ft = "" if title == "__title__" else f'<div class="ft"><span>Self-Healing Cloud Security - CSL-384</span><span>{i + 1} / {n}</span></div>'
        out.append(f'<section class="s">{head}{body}{ft}</section>')
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{''.join(out)}</body></html>"


async def main():
    from playwright.async_api import async_playwright
    d = os.path.dirname(os.path.abspath(__file__))
    html = os.path.join(d, "deck.html")
    open(html, "w").write(render_html())
    os.makedirs(os.path.join(d, "png"), exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1920, "height": 1080})
        await pg.goto("file://" + html)
        await pg.wait_for_timeout(800)
        await pg.pdf(path=os.path.join(d, "Self_Healing_Cloud_Security_Final.pdf"), width="1920px", height="1080px", print_background=True)
        for i, el in enumerate(await pg.query_selector_all("section.s")):
            await el.screenshot(path=os.path.join(d, "png", f"slide{i + 1:02d}.png"))
        await b.close()
    print("slides:", len(slides))


if __name__ == "__main__":
    asyncio.run(main())
