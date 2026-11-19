"""Bake results/ into a single self-contained docs/index.html (GitHub Pages / Cloudflare Pages)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from selfheal.tools import TOOLS  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
repo = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/jatinsingh1603/self-healing-cloud-security"
results = json.load(open(os.path.join(ROOT, "results", "results.json")))
replay = json.load(open(os.path.join(ROOT, "results", "replay.json")))
for d in replay.values():          # keep the page small
    for o in d["outcomes"]:
        o.pop("evidence", None)
for d in results["datasets"].values():
    d.pop("mismatches_raw", None)
tools = [{"name": t.name, "fixes": t.fixes.value, "risk": t.risk, "actions": list(t.actions), "description": t.description} for t in TOOLS.values()]
html = open(os.path.join(os.path.dirname(__file__), "template.html")).read()
html = (html.replace("/*RESULTS*/null", json.dumps(results, separators=(",", ":")))
            .replace("/*REPLAY*/null", json.dumps(replay, separators=(",", ":")))
            .replace("/*TOOLS*/null", json.dumps(tools, separators=(",", ":")))
            .replace("__REPO__", repo))
chart = os.path.join(os.path.dirname(__file__), "chart.umd.min.js")
html = html.replace('<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>',
                    "<script>" + open(chart).read().replace("</script", "<\\/script") + "</script>")
os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
open(os.path.join(ROOT, "docs", "index.html"), "w").write(html)
print("docs/index.html", len(html) // 1024, "KB")
