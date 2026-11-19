"""Render the report/deck figures from results/results.json into results/figures/."""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
R = json.load(open(os.path.join(ROOT, "results", "results.json")))
OUT = os.path.join(ROOT, "results", "figures")
os.makedirs(OUT, exist_ok=True)

INK, MUT, GRID = "#111827", "#5f6b7a", "#e6e8ec"
BLUE, LBLUE, GREEN, AMBER, RED, GREY, TEAL = "#1f4fd1", "#8fa8ea", "#2e8b57", "#c58a1b", "#c0392b", "#9aa4b2", "#3a8fa3"
plt.rcParams.update({
    "font.family": "Inter", "font.size": 13, "axes.edgecolor": GRID, "axes.labelcolor": MUT, "xtick.color": MUT,
    "ytick.color": MUT, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
    "axes.axisbelow": True, "axes.titleweight": "semibold", "axes.titlesize": 13, "axes.titlecolor": INK,
    "axes.titlelocation": "left", "legend.frameon": False, "figure.dpi": 200, "savefig.bbox": "tight",
})
DS = list(R["datasets"])
pctfmt = matplotlib.ticker.PercentFormatter(1.0, decimals=0)


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), facecolor="white")
    plt.close(fig)


# 1. accuracy per dataset (raw vs adjudicated)
fig, ax = plt.subplots(figsize=(8, 3.8))
metrics = [("precision", LBLUE), ("recall", GREEN), ("f1", BLUE)]
x, labels = 0, []
for d in DS:
    for k in ("raw", "adjudicated"):
        o = R["datasets"][d][f"accuracy_{k}"]["overall"]
        for i, (m, c) in enumerate(metrics):
            ax.bar(x + i * 0.26, o[m], 0.24, color=c, label=m.upper() if x == 0 else None)
        ax.text(x + 0.26, o["f1"] + 0.02, f"{o['f1']:.2f}", ha="center", fontsize=11, color=INK)
        labels.append((x + 0.26, f"{d}\n{'raw' if k == 'raw' else 'adjudicated'}"))
        x += 1
ax.set_xticks([p for p, _ in labels], [l for _, l in labels], fontsize=11)
ax.set_ylim(0, 1.12); ax.yaxis.set_major_formatter(pctfmt)
ax.set_title("Detection vs ground truth (Checkov labels)")
ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.2), fontsize=11)
save(fig, "e1_accuracy.png")

# 2. per rule (pooled, raw)
rules = sorted({r for d in DS for r in R["datasets"][d]["accuracy_raw"]["per_rule"]})
rows = []
for r in rules:
    t = dict(tp=0, fp=0, fn=0, tn=0)
    for d in DS:
        x_ = R["datasets"][d]["accuracy_raw"]["per_rule"].get(r)
        if x_:
            for k in t:
                t[k] += x_[k]
    acc = (t["tp"] + t["tn"]) / sum(t.values())
    rows.append((r, acc, sum(t.values())))
fig, ax = plt.subplots(figsize=(8, 4.9))
NAMES = {"S3_PUBLIC_ACCESS": "S3 public access", "S3_VERSIONING_DISABLED": "S3 versioning off", "S3_NO_KMS_ENCRYPTION": "S3 no KMS", "SG_OPEN_SSH": "SG open SSH", "SG_OPEN_RDP": "SG open RDP", "SG_OPEN_ALL_PORTS": "SG all ports open", "CLOUDTRAIL_NOT_MULTI_REGION": "Trail single-region", "CLOUDTRAIL_NO_LOG_VALIDATION": "Trail no validation", "IAM_ADMIN_WILDCARD": "IAM Action *"}
ax.barh([f"{NAMES.get(r, r)} (n={n})" for r, _, n in rows][::-1], [a for _, a, _ in rows][::-1], color=BLUE, height=0.6)
for i, (_, a, _) in enumerate(rows[::-1]):
    ax.text(a + 0.01, i, f"{a:.0%}", va="center", fontsize=11, color=INK)
ax.set_xlim(0, 1.1); ax.xaxis.set_major_formatter(pctfmt); ax.tick_params(axis="y", labelsize=9)
ax.set_title("Accuracy per rule, pooled over 3 datasets (raw labels)")
save(fig, "e1_per_rule.png")

# 3. remediation outcomes
fig, ax = plt.subplots(figsize=(8, 3.6))
statuses = [("HEALED", GREEN), ("ALREADY_RESOLVED", TEAL), ("ESCALATED", AMBER), ("NOT_HEALED", RED), ("BLOCKED", GREY)]
bottom = [0] * len(DS)
for s, c in statuses:
    v = [sum(r["status"].get(s, 0) for r in R["e2"][d]["runs"]) / len(R["e2"][d]["runs"]) for d in DS]
    if any(v):
        ax.bar(DS, v, 0.5, bottom=bottom, color=c, label=s.replace("_", " ").title())
        bottom = [b + x_ for b, x_ in zip(bottom, v)]
for i, d in enumerate(DS):
    ax.text(i, bottom[i] + 1, f"heal rate {R['e2'][d]['heal_rate_mean']:.0%}", ha="center", fontsize=11, color=INK)
ax.set_ylim(0, max(bottom) * 1.18); ax.set_ylabel("findings per run")
ax.set_title(f"Remediation outcome per finding (mean of {R['runs']} runs)")
ax.legend(fontsize=11, loc="upper left")
save(fig, "e2_outcomes.png")

# 4. timings
fig, ax = plt.subplots(figsize=(8, 3.6))
stages = [("detect", BLUE), ("decide", GREY), ("fix", GREEN), ("verify", TEAL)]
for i, (s, c) in enumerate(stages):
    v = [(R["e2"][d]["timings_ms"].get(s) or {}).get("mean", 0) for d in DS]
    ax.bar([j + i * 0.2 for j in range(len(DS))], v, 0.18, color=c, label=s + (" (account)" if s == "detect" else " (per finding)"))
ax.set_yscale("log"); ax.set_xticks([j + 0.3 for j in range(len(DS))], DS); ax.set_ylabel("ms (log)")
ax.set_title("Mean stage time on emulated AWS")
ax.legend(fontsize=11, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.12))
save(fig, "e2_timing.png")

# 5. E3 robustness
errs = sorted({x["error_rate"] for x in R["e3"]})
cfgs = list(dict.fromkeys(x["config"] for x in R["e3"]))
cols = [BLUE, GREEN, AMBER, RED]
fig, axs = plt.subplots(1, 2, figsize=(10, 3.6))
for k, (key, title) in enumerate([("true_fix_rate", "Findings truly fixed"), ("wrong_tool_executed_rate", "Wrong tool executed on a resource")]):
    for c, col, ls in zip(cfgs, cols, ["-", "-", (0, (6, 3)), (0, (1, 2))]):
        axs[k].plot([e * 100 for e in errs], [next(x[key] for x in R["e3"] if x["config"] == c and x["error_rate"] == e) for e in errs],
                    marker="o", color=col, label=c, lw=2.2, ms=4, ls=ls)
    axs[k].set_title(title); axs[k].yaxis.set_major_formatter(pctfmt); axs[k].set_xlabel("AI mistake rate (%)")
axs[0].set_ylim(0, 1.05)
axs[1].legend(fontsize=10.5, loc="upper left")
save(fig, "e3_robustness.png")

# 6. E4 faults
sn = list(dict.fromkeys(x["scenario"] for x in R["e4"]))
fig, ax = plt.subplots(figsize=(10, 3.6))
for i, (v, col, lab) in enumerate([(False, RED, "no verification"), (True, GREEN, "with independent verification")]):
    ax.bar([j + i * 0.36 for j in range(len(sn))], [next(x["false_heal_claim_rate"] for x in R["e4"] if x["scenario"] == s and x["verification"] == v) for s in sn],
           0.34, color=col, label=f"false 'healed' claims, {lab}")
ax.set_xticks([j + 0.18 for j in range(len(sn))], [s.replace(" p=", "\np=").replace(" k=", "\nk=") for s in sn], fontsize=11)
for j, s_ in enumerate(sn):
    ax.text(j + 0.36, 0.008, "0%" if next(x["false_heal_claim_rate"] for x in R["e4"] if x["scenario"] == s_ and x["verification"]) == 0 else "", ha="center", fontsize=10, color=GREEN)
ax.yaxis.set_major_formatter(pctfmt); ax.set_title("Injected cloud faults: findings reported healed that were not")
ax.legend(fontsize=11)
save(fig, "e4_faults.png")
print("figures ->", OUT, sorted(os.listdir(OUT)))
