"""Record one full self-healing run per dataset for the website's replay view."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="us-east-1")
from moto import mock_aws  # noqa: E402

from run_all import DATASETS  # noqa: E402
from selfheal import checks, loader  # noqa: E402
from selfheal.engine import Config, SelfHealer  # noqa: E402
from selfheal.guard import GuardedSession, reader_identity  # noqa: E402

base = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", "datasets")
out = {}
for ds, meta in DATASETS.items():
    root = os.path.join(base, ds, meta["path"]) if meta["path"] else os.path.join(base, ds)
    mods = loader.parse_dataset(root, ds)
    with mock_aws():
        loader.deploy(mods)
        h = SelfHealer(config=Config(verify_backoff_s=0.0))
        res = h.run()
        left = checks.scan(GuardedSession(reader_identity()))
    out[ds] = {
        "detect_ms": round(res["t_detect_ms"], 1),
        "outcomes": [{
            "rule": o.finding.rule.value, "severity": o.finding.severity, "resource": o.finding.resource_id,
            "tf": o.finding.source_ref, "tool": o.tool, "status": o.status.value, "detail": o.detail,
            "api_calls": o.api_calls, "attempts": o.attempts,
            "ms": round(o.t_decide_ms + o.t_fix_ms + o.t_verify_ms, 2), "evidence": o.finding.evidence,
        } for o in res["outcomes"]],
        "left_after": [f.key for f in left],
    }
    print(ds, len(out[ds]["outcomes"]), "left", len(left))
json.dump(out, open(os.path.join(os.path.dirname(__file__), "..", "results", "replay.json"), "w"), indent=1, default=str)
