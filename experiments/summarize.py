"""Write the results section of README.md from results/results.json."""
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
R = json.load(open(os.path.join(ROOT, "results", "results.json")))
DS = list(R["datasets"])
pc = lambda x: f"{x * 100:.1f}%"
L = [f"All numbers: `experiments/run_all.py`, {R['runs']} repeated runs, generated {R['generated']}.", "",
     "**E1 Detection accuracy vs Checkov labels**", "",
     "| Dataset | Labels | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |", "|---|---|---|---|---|---|---|---|---|---|"]
tot = {k: dict(tp=0, fp=0, fn=0, tn=0) for k in ("raw", "adjudicated")}
for d in DS:
    for k in ("raw", "adjudicated"):
        o = R["datasets"][d][f"accuracy_{k}"]["overall"]
        for m in tot[k]:
            tot[k][m] += o[m]
        L.append(f"| {d} | {k} | {o['tp']} | {o['fp']} | {o['fn']} | {o['tn']} | {o['precision']:.3f} | {o['recall']:.3f} | {o['f1']:.3f} | {pc(o['accuracy'])} |")
for k, t in tot.items():
    p, r = t["tp"] / (t["tp"] + t["fp"]), t["tp"] / (t["tp"] + t["fn"])
    L.append(f"| **all three** | {k} | {t['tp']} | {t['fp']} | {t['fn']} | {t['tn']} | {p:.3f} | {r:.3f} | **{2 * p * r / (p + r):.3f}** | **{pc((t['tp'] + t['tn']) / sum(t.values()))}** |")
L += ["", "**E2 Remediation** (auto-fixable findings healed and verified by the independent re-check)", "",
      "| Dataset | Findings | Healed | Already resolved | Escalated (HIGH risk) | Heal rate | Detect ms | Fix ms / finding | Verify ms / finding |", "|---|---|---|---|---|---|---|---|---|"]
for d in DS:
    e = R["e2"][d]; s = e["runs"][-1]["status"]; t = e["timings_ms"]
    L.append(f"| {d} | {e['runs'][-1]['findings']} | {s.get('HEALED', 0)} | {s.get('ALREADY_RESOLVED', 0)} | {s.get('ESCALATED', 0)} | {pc(e['heal_rate_mean'])} | {t['detect']['mean']:.0f} | {t['fix']['mean']:.1f} | {t['verify']['mean']:.1f} |")
L += ["", "**E3 Simulated AI that picks the wrong tool**", "", "| AI error rate | Config | Truly fixed | Wrong tool executed | False 'healed' claims |", "|---|---|---|---|---|"]
for x in R["e3"]:
    if x["error_rate"] in (0.1, 0.3, 0.5):
        L.append(f"| {int(x['error_rate'] * 100)}% | {x['config']} | {pc(x['true_fix_rate'])} | {pc(x['wrong_tool_executed_rate'])} | {pc(x['false_heal_claim_rate'])} |")
L += ["", "**E4 Injected cloud faults**", "", "| Scenario | Verification | Truly fixed | False 'healed' claims | Avg attempts |", "|---|---|---|---|---|"]
for x in R["e4"]:
    L.append(f"| {x['scenario']} | {'on' if x['verification'] else 'off'} | {pc(x['true_fix_rate'])} | {pc(x['false_heal_claim_rate'])} | {x['avg_attempts']} |")
e5 = R["e5"]
L += ["", f"**E5 Least privilege:** {e5['blocked']}/{e5['out_of_policy_calls']} out-of-policy calls blocked; {e5['verifier_write_actions_denied']}/{e5['verifier_write_actions_total']} write actions denied to the verifier.",
      "", "Figures: `results/figures/`. Every Checkov disagreement and how it was resolved: `experiments/adjudication.json` and the website's Results section."]
p = os.path.join(ROOT, "README.md")
s = open(p).read()
start = s.index("<!--RESULTS-->")
end = s.index("## 5. Run it")
open(p, "w").write(s[:start] + "<!--RESULTS-->\n" + "\n".join(L) + "\n\n" + s[end:])
print("README results updated")
