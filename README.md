# Self-Healing Cloud Security

**AI-driven detection, remediation and independent verification of AWS misconfigurations.**
Final project for CSL-384 Cloud Security Essentials, The NorthCap University (faculty: Arun Kumar Jindal).

| | |
|---|---|
| Live demo | https://jatinsingh1603.github.io/self-healing-cloud-security/ |
| Presentation | [`presentation/Self_Healing_Cloud_Security_Final.pdf`](presentation/Self_Healing_Cloud_Security_Final.pdf) |
| Demo video | [`presentation/Self_Healing_Cloud_Security_Demo.mp4`](presentation/Self_Healing_Cloud_Security_Demo.mp4) |

**Team:** Jatin (23CSU141), Deepanshu (23CSU091), Yana (23CSU395), Ishant (23CSU130), Indresh (23CSU128)

---

## 1. Problem

Cloud configuration drifts every day. One change can make an S3 bucket public, open SSH to the internet or switch off CloudTrail, and the exposure lasts until a person notices and fixes it. Scanners only report; auto-remediation scripts trust that an API returning `200 OK` means the resource is safe; and letting an AI agent act on production raises a new risk: a wrong or invented action.

## 2. What we built

A closed control loop with four stages and three separate identities:

```
            +-----------+     +-----------+     +-------------+     +-----------+
 AWS  --->  | 01 DETECT | --> | 02 DECIDE | --> |   03 FIX    | --> | 04 VERIFY |
account     | read-only |     | AI or rule|     | least-priv. |     | separate  |
  ^         | 10 rules  |     | guardrail |     | HIGH->human |     | read-only |
  |         +-----------+     +-----------+     +-------------+     +-----------+
  +---------------------- HEALED / NOT HEALED -> audit log ----------------+
```

* **Detect** (`selfheal/checks.py`): the `SelfHealReader` identity (Get/List/Describe only) evaluates 10 CIS-aligned rules on live configuration: S3 public access, versioning, KMS encryption; security groups open to the internet on SSH, RDP or all ports; CloudTrail missing, not logging, single-region, no log validation; IAM policies with `Action: *`.
* **Decide** (`selfheal/decide.py`): an LLM (Anthropic, any OpenAI-compatible endpoint or an n8n agent webhook) or the fixed rule selector picks **one** tool from the approved registry. A guardrail rejects any tool that does not exist or is not approved for that rule; optionally it falls back to the rule selector.
* **Fix** (`selfheal/tools.py`, `selfheal/guard.py`): the `SelfHealRemediator` identity may call only the IAM actions the approved tools declare (see `iam/remediator-policy.json`). Every boto3 call is checked before it leaves the process. HIGH-risk tools (IAM quarantine) are escalated to a human.
* **Verify** (`selfheal/engine.py`): a second, independent read-only identity re-runs the exact same check on that one resource, with backoff for eventual consistency; one retry, then `HEALED` or `NOT_HEALED`. Every outcome and API call goes to a JSONL audit log.

Fixes are surgical: revoking `tcp/22` from `0.0.0.0/0` leaves `tcp/443` open; quarantining an admin policy keeps the old version for rollback.

## 3. Datasets (all public)

| Dataset | Publisher | What it is |
|---|---|---|
| [TerraGoat](https://github.com/bridgecrewio/terragoat) | Bridgecrew / Palo Alto Networks | "Vulnerable by design" Terraform for AWS |
| [sadcloud](https://github.com/nccgroup/sadcloud) | NCC Group | Terraform that spins up deliberately insecure AWS infrastructure |
| [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) | Rhino Security Labs | Vulnerable-by-design AWS scenarios (33 Terraform modules) |

`selfheal/loader.py` parses each dataset's Terraform (variables, locals, conditionals) and creates every in-scope resource through boto3 in an emulated AWS account ([moto](https://github.com/getmoto/moto)), as `terraform apply` would. The loop then runs on the deployed state.

**Ground truth:** [Checkov](https://github.com/bridgecrewio/checkov) labels the same CIS properties on the source; every (resource, rule) pair is scored. Every disagreement was reviewed by hand and is documented in `experiments/adjudication.json`; we report both raw and adjudicated numbers.

## 4. Results

<!--RESULTS-->
All numbers: `experiments/run_all.py`, 5 repeated runs, generated 2026-11-19 17:28:57.

**E1 Detection accuracy vs Checkov labels**

| Dataset | Labels | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|---|---|---|
| terragoat | raw | 15 | 0 | 0 | 11 | 1.000 | 1.000 | 1.000 | 100.0% |
| terragoat | adjudicated | 15 | 0 | 0 | 11 | 1.000 | 1.000 | 1.000 | 100.0% |
| sadcloud | raw | 26 | 4 | 3 | 35 | 0.867 | 0.897 | 0.881 | 89.7% |
| sadcloud | adjudicated | 30 | 0 | 0 | 38 | 1.000 | 1.000 | 1.000 | 100.0% |
| cloudgoat | raw | 61 | 0 | 14 | 176 | 1.000 | 0.813 | 0.897 | 94.4% |
| cloudgoat | adjudicated | 60 | 0 | 0 | 119 | 1.000 | 1.000 | 1.000 | 100.0% |
| **all three** | raw | 102 | 4 | 17 | 222 | 0.962 | 0.857 | **0.907** | **93.9%** |
| **all three** | adjudicated | 105 | 0 | 0 | 168 | 1.000 | 1.000 | **1.000** | **100.0%** |

**E2 Remediation** (auto-fixable findings healed and verified by the independent re-check)

| Dataset | Findings | Healed | Already resolved | Escalated (HIGH risk) | Heal rate | Detect ms | Fix ms / finding | Verify ms / finding |
|---|---|---|---|---|---|---|---|---|
| terragoat | 16 | 16 | 0 | 0 | 100.0% | 268 | 13.5 | 7.6 |
| sadcloud | 31 | 25 | 4 | 2 | 100.0% | 277 | 8.7 | 6.9 |
| cloudgoat | 61 | 59 | 0 | 2 | 100.0% | 833 | 7.4 | 7.6 |

**E3 Simulated AI that picks the wrong tool**

| AI error rate | Config | Truly fixed | Wrong tool executed | False 'healed' claims |
|---|---|---|---|---|
| 10% | guardrail+verify | 85.2% | 0.0% | 0.0% |
| 10% | guardrail+fallback+verify | 100.0% | 0.0% | 0.0% |
| 10% | no-guardrail+verify | 86.1% | 8.7% | 0.0% |
| 10% | no-guardrail,no-verify | 86.1% | 8.7% | 8.5% |
| 30% | guardrail+verify | 73.0% | 0.0% | 0.0% |
| 30% | guardrail+fallback+verify | 100.0% | 0.0% | 0.0% |
| 30% | no-guardrail+verify | 75.0% | 16.4% | 0.0% |
| 30% | no-guardrail,no-verify | 75.0% | 16.4% | 15.6% |
| 50% | guardrail+verify | 52.6% | 0.0% | 0.0% |
| 50% | guardrail+fallback+verify | 100.0% | 0.0% | 0.0% |
| 50% | no-guardrail+verify | 57.1% | 30.8% | 0.0% |
| 50% | no-guardrail,no-verify | 57.1% | 30.8% | 28.7% |

**E4 Injected cloud faults**

| Scenario | Verification | Truly fixed | False 'healed' claims | Avg attempts |
|---|---|---|---|---|
| baseline | on | 100.0% | 0.0% | 0.962 |
| baseline | off | 100.0% | 0.0% | 0.962 |
| stale reads k=2 | on | 100.0% | 0.0% | 0.962 |
| stale reads k=2 | off | 100.0% | 0.0% | 0.962 |
| stale reads k=6 | on | 100.0% | 0.0% | 1.923 |
| stale reads k=6 | off | 100.0% | 0.0% | 0.962 |
| partial fix p=0.3 | on | 100.0% | 0.0% | 1.221 |
| partial fix p=0.3 | off | 74.0% | 26.0% | 0.975 |
| transient error p=0.2 | on | 100.0% | 0.0% | 1.121 |
| transient error p=0.2 | off | 83.9% | 16.2% | 0.967 |
| all faults | on | 100.0% | 0.0% | 1.415 |
| all faults | off | 54.4% | 45.6% | 0.975 |

**E5 Least privilege:** 10/10 out-of-policy calls blocked; 22/22 write actions denied to the verifier.

Figures: `results/figures/`. Every Checkov disagreement and how it was resolved: `experiments/adjudication.json` and the website's Results section.

## 5. Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m selfheal demo               # the 3 deck scenarios + extras on an emulated account
python -m selfheal demo --approve     # also apply the HIGH-risk IAM fix
python -m selfheal policy             # print the least-privilege IAM policies
python -m pytest -q                   # 11 tests

bash experiments/get_datasets.sh ../datasets
python experiments/run_all.py --datasets-dir ../datasets --runs 5   # all experiments -> results/results.json
python experiments/make_charts.py                                   # figures -> results/figures/
python experiments/replay.py ../datasets                            # recorded runs for the website
python site/build.py                                                # website -> docs/index.html
```

**Real AWS account** (uses your normal AWS credentials; attach `iam/remediator-policy.json` to the role you run it with):

```bash
python -m selfheal scan --live                 # read-only
python -m selfheal heal --live                 # dry run: shows what it would do
python -m selfheal heal --live --yes           # apply LOW/MEDIUM-risk fixes, verify each one
SELFHEAL_LLM=anthropic ANTHROPIC_API_KEY=... python -m selfheal heal --live --yes --selector llm
```

## 6. Repository layout

```
selfheal/        engine: model, checks (detect), decide (AI/rule + guardrail), tools, guard (least privilege),
                 engine (loop), loader (Terraform -> AWS), labels (Checkov ground truth), faults, scenarios, CLI
experiments/     run_all.py (E1-E5), replay.py, make_charts.py, adjudication.json, get_datasets.sh
results/         results.json, replay.json, figures/, raw Checkov outputs
iam/             remediator-policy.json, reader-policy.json
site/            website template + build script;  docs/ = built site (GitHub Pages)
presentation/    final PDF deck and demo video
tests/           pytest suite
```

## 7. Limitations

Experiments run on the moto AWS emulator, which uses the real boto3 API surface but not real AWS latency or every service behaviour. The "AI" in the robustness experiment is a simulated error model so that error rates can be controlled; a real LLM plugs into the same interface. Checkov is a strong but imperfect reference; we show its errors explicitly rather than hiding them.
