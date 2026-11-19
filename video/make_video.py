"""Narrated demo video: slides + live recordings of the website, voiced with Kokoro TTS.

python video/make_video.py  -> presentation/Self_Healing_Cloud_Security_Demo.mp4
"""
import asyncio
import json
import os
import subprocess
import time

import soundfile as sf

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
W = os.path.join(ROOT, "video", "work")
SITE = "file://" + os.path.join(ROOT, "docs", "index.html")
SLIDES = os.path.join(ROOT, "deck", "png")
TTS = "/home/claude/tts"
R = json.load(open(os.path.join(ROOT, "results", "results.json")))
os.makedirs(W, exist_ok=True)
FPS = 30
ENC = ["-c:v", "libx264", "-crf", "20", "-preset", "veryfast", "-pix_fmt", "yuv420p", "-r", str(FPS)]

DS = list(R["datasets"])
def pool(kind):
    t = dict(tp=0, fp=0, fn=0, tn=0)
    for d in DS:
        for k in t:
            t[k] += R["datasets"][d][f"accuracy_{kind}"]["overall"][k]
    p, r = t["tp"] / (t["tp"] + t["fp"]), t["tp"] / (t["tp"] + t["fn"])
    return sum(t.values()), (t["tp"] + t["tn"]) / sum(t.values()), 2 * p * r / (p + r)
N, ACC, F1 = pool("raw")
af = {x["verification"]: x for x in R["e4"] if x["scenario"] == "all faults"}
spk = lambda x: f"{x * 100:.1f}".rstrip("0").rstrip(".")

SCENES = [
    ("slide", "slide01.png", "This is Self-Healing Cloud Security, our final project for Cloud Security Essentials. "
     "It is a tool that finds security misconfigurations in an A W S account, fixes them automatically, and then proves that every fix actually worked."),
    ("slide", "slide02.png", "The problem is configuration drift. In the cloud, one click can make a storage bucket public, open S S H to the whole internet, "
     "or switch off CloudTrail audit logging. Scanners only report these issues, so a person still has to fix each one. Automation scripts assume that a successful A P I call means the resource is safe. "
     "And if an A I agent is allowed to make changes, something has to stop it from taking a wrong or invented action."),
    ("slide", "slide04.png", "Our solution is a closed control loop with four stages. Detect reads the live configuration with a read-only identity and checks ten C I S aligned rules. "
     "Decide lets an A I agent choose one fix, but only from a registry of approved tools, and a guardrail rejects anything else. "
     "Fix applies the change through a least privilege identity that can call only the A P I actions those tools need. "
     "Verify uses a separate read-only identity to check the resource again, so nothing is marked healed until the cloud confirms it."),
    ("slide", "slide05.png", "Each misconfiguration maps to one approved tool, with a risk level and the exact permissions it is allowed. "
     "Low and medium risk fixes run automatically. A high risk change, such as quarantining an administrator policy, always waits for a human."),
    ("rec_heal", None, "Here is the tool we built, running live. This account has a public bucket, S S H and remote desktop open to the internet, CloudTrail problems, and an admin policy. "
     "We press run. The engine detects every finding, picks the approved fix for each one, applies it, and confirms it with an independent re-check. "
     "The cards turn green one by one, and the admin policy is held for approval. When we approve it, that last finding is fixed and verified as well."),
    ("rec_ai", None, "Now we switch to an A I decision maker that makes mistakes forty percent of the time, and we turn off the guardrail and the re-check. "
     "The A I runs wrong tools, and findings are reported as healed when they are still open. "
     "With the safety layers back on, every bad choice is blocked before any A P I call, the safe fallback picks the right tool, and the account ends up clean."),
    ("terminal", None, "The same engine is a Python package. One command runs the whole loop on an emulated A W S account through real boto three A P I calls, "
     "and the same code can run against a live account with a least privilege I A M policy."),
    ("rec_ds", None, "To test accuracy on real data, we used three public, deliberately vulnerable A W S datasets: TerraGoat from Bridgecrew, sadcloud from N C C Group, and CloudGoat from Rhino Security Labs. "
     "Each one is deployed into an emulated account and healed end to end. Every row here is a finding from a recorded run, with the tool used and the exact A P I calls that were made."),
    ("slide", "slide08.png", f"Against Checkov labels on {N} labelled resource and rule pairs, detection reached {spk(ACC)} percent accuracy, with an F one score of {F1:.2f}. "
     "We reviewed every disagreement by hand, and several turned out to be errors in Checkov itself, such as treating an I C M P rule as open S S H."),
    ("slide", "slide11.png", f"Every auto-fixable finding was healed and verified in all {R['runs']} repeated runs. When we simulated an A I that picks the wrong tool, the guardrail kept wrong tool executions at zero, "
     "at every error rate we tested."),
    ("slide", "slide12.png", f"When we injected cloud faults such as partial fixes, stale reads and throttling, {spk(af[False]['false_heal_claim_rate'])} percent of findings were falsely reported as healed without verification. "
     f"With our independent re-check and one retry, that dropped to {spk(af[True]['false_heal_claim_rate'])} percent. And the least privilege guard blocked every dangerous call we tried."),
    ("slide", "slide14.png", "So what does it solve? It closes the gap between finding a misconfiguration and having a proven fix, in under a second per finding on our test account. "
     "It makes A I driven remediation safe, through approved tools, least privilege and human approval for risky changes. And it never claims a fix it cannot prove."),
    ("slide", "slide16.png", "The live demo and the full source code are available at these links. Thank you."),
]


def tts():
    from kokoro_onnx import Kokoro
    k = Kokoro(f"{TTS}/kokoro-v1.0.int8.onnx", f"{TTS}/voices-v1.0.bin")
    lens = []
    for i, (_, _, text) in enumerate(SCENES):
        p = f"{W}/a{i:02d}.wav"
        if os.path.exists(p):
            lens.append(sf.info(p).duration); continue
        s, sr = k.create(text, voice="am_michael", speed=1.0, lang="en-us")
        sf.write(p, s, sr)
        lens.append(len(s) / sr)
    return lens


def still(png, dur, out):
    tmp = out.replace(".mp4", ".tmp.mp4")
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-framerate", str(FPS), "-i", png, "-vf",
                    f"scale=1920:1080,format=yuv420p,loop=-1:1,trim=duration={dur:.3f},fade=t=in:st=0:d=0.35",
                    *ENC, tmp], check=True)
    os.replace(tmp, out)


def frames_to_mp4(frames, dur, out):
    """frames: [(path, t)] captured at irregular times; hold the last frame to `dur`."""
    lst = f"{out}.txt"
    with open(lst, "w") as f:
        for j, (p, t) in enumerate(frames):
            nxt = frames[j + 1][1] if j + 1 < len(frames) else max(dur, t + 0.5)
            f.write(f"file '{p}'\nduration {max(nxt - t, 0.034):.3f}\n")
        f.write(f"file '{frames[-1][0]}'\n")
    tmp = out.replace(".mp4", ".tmp.mp4")
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0", "-i", lst, "-vf",
                    f"scale=1920:1080,format=yuv420p,trim=duration={dur:.3f},fade=t=in:st=0:d=0.35", *ENC, tmp], check=True)
    os.replace(tmp, out)


class Recorder:
    def __init__(self, page, name):
        self.page, self.name, self.frames, self.t0, self.on = page, name, [], None, False

    async def loop(self):
        self.t0 = time.perf_counter()
        i = 0
        while self.on:
            p = f"{W}/{self.name}_{i:05d}.jpg"
            await self.page.screenshot(path=p, type="jpeg", quality=92)
            self.frames.append((p, time.perf_counter() - self.t0))
            i += 1
            await asyncio.sleep(0.02)

    def start(self):
        self.on = True
        self.task = asyncio.create_task(self.loop())

    async def stop(self):
        self.on = False
        await self.task
        return self.frames


async def record(kind, dur):
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1440, "height": 810}, device_scale_factor=4 / 3)
        await pg.goto(SITE)
        await pg.add_style_tag(content="nav{display:none}html{scroll-behavior:auto}.console{height:300px}.ctrl{position:static}")
        await pg.wait_for_timeout(600)
        rec = Recorder(pg, kind)
        if kind in ("rec_heal", "rec_ai"):
            await pg.evaluate("window.scrollTo(0, document.querySelector('#demo .demo').getBoundingClientRect().top + scrollY - 14)")
            await pg.evaluate("document.querySelector(\"#scen button[data-v='full']\").click()")
            await pg.evaluate("document.querySelector(\"#spd button[data-v='1']\").click()")
            if kind == "rec_ai":
                await pg.evaluate("document.querySelector(\"#sel button[data-v='ai']\").click()")
                await pg.evaluate("document.querySelector('#err').value=40; document.querySelector('#err').dispatchEvent(new Event('input'))")
                for k in ("guardrail", "fallback", "verify"):
                    await pg.evaluate(f"document.querySelector(\".tog[data-k='{k}']\").click()")
                await pg.evaluate("Math.random = (function(){let s=7;return function(){s=(s*16807)%2147483647;return (s-1)/2147483646}})()")
            rec.start()
            await pg.wait_for_timeout(1500)
            await pg.evaluate("document.querySelector(\"#runBtn\").click()")
            await pg.wait_for_function("!document.querySelector('#runBtn').disabled", timeout=120000)
            await pg.wait_for_timeout(1200)
            if kind == "rec_heal":
                await pg.evaluate("document.querySelector(\"#okBtn\").click()")
                await pg.wait_for_timeout(4000)
            else:
                for k in ("guardrail", "fallback", "verify"):
                    await pg.evaluate(f"document.querySelector(\".tog[data-k='{k}']\").click()")
                    await pg.wait_for_timeout(350)
                await pg.evaluate("document.querySelector(\"#resetBtn\").click()")
                await pg.wait_for_timeout(600)
                await pg.evaluate("document.querySelector(\"#spd button[data-v='0.25']\").click()")
                await pg.evaluate("document.querySelector(\"#runBtn\").click()")
                await pg.wait_for_function("!document.querySelector('#runBtn').disabled", timeout=120000)
                await pg.wait_for_timeout(2500)
        elif kind == "rec_ds":
            await pg.evaluate("window.scrollTo(0, document.querySelector('#datasets').getBoundingClientRect().top + scrollY + 20)")
            rec.start()
            await pg.wait_for_timeout(2500)
            for d in ("sadcloud", "cloudgoat"):
                await pg.evaluate(f"document.querySelector(\"#dsTabs button[data-d='{d}']\").click()")
                await pg.wait_for_timeout(2500)
            for _ in range(25):   # bring the table up, gently
                await pg.evaluate("window.scrollBy(0, 12)")
                await pg.wait_for_timeout(40)
            await pg.wait_for_timeout(1200)
            for _ in range(150):   # scroll slowly through the findings inside the table
                await pg.evaluate("document.querySelector('#dsTable').parentElement.scrollBy(0, 6)")
                await pg.wait_for_timeout(70)
            await pg.wait_for_timeout(1500)
        frames = await rec.stop()
        await b.close()
    real = frames[-1][1]
    print(kind, "recorded", round(real, 1), "s for", round(dur, 1), "s of narration")
    return frames, real


def terminal_png(out):
    os.environ["NO_COLOR"] = "1"
    txt = subprocess.run(["python3", "-m", "selfheal", "demo", "--audit", f"{W}/audit.jsonl"], cwd=ROOT, capture_output=True, text=True).stdout
    import html
    lines = [l for l in txt.splitlines() if "Warning" not in l]
    def col(l):
        e = html.escape(l)
        for w, c in (("HEALED", "#1e7d4f"), ("ESCALATED", "#9a6700"), ("ALREADY_RESOLVED", "#0e7490"), ("CRITICAL", "#8f1d14")):
            e = e.replace(w, f'<b style="color:{c}">{w}</b>')
        for w in ("DETECT", "DECIDE &gt; FIX &gt; VERIFY", "RESULT", "RE-SCAN"):
            e = e.replace(w, f'<b style="color:#1f4fd1">{w}</b>')
        return e
    body = "\n".join(col(l) for l in lines)
    page = f"""<html><body style="margin:0;background:#fff;font-family:Inter,sans-serif">
<div style="width:1920px;height:1080px;padding:60px 120px;box-sizing:border-box">
<div style="font-size:20px;font-weight:600;letter-spacing:.07em;color:#1f4fd1">THE TOOL - PYTHON ENGINE</div>
<div style="font-size:44px;font-weight:600;margin:6px 0 24px">$ python -m selfheal demo</div>
<pre style="font:17.5px/1.5 'JetBrains Mono',monospace;background:#f6f7f9;border:1px solid #e6e8ec;border-radius:10px;padding:22px 28px;margin:0;color:#1f2937;height:850px;overflow:hidden">{body}</pre></div></body></html>"""
    hp = f"{W}/term.html"
    open(hp, "w").write(page)

    async def shot():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch()
            pg = await b.new_page(viewport={"width": 1920, "height": 1080})
            await pg.goto("file://" + hp)
            await pg.screenshot(path=out)
            await b.close()
    asyncio.run(shot())


def main():
    lens = tts()
    parts = []
    for i, ((kind, src, _), alen) in enumerate(zip(SCENES, lens)):
        dur = alen + 0.9
        out = f"{W}/v{i:02d}.mp4"
        only = os.environ.get("ONLY")
        if only and str(i) not in only.split(",") and os.path.exists(out):
            parts.append((out, f"{W}/a{i:02d}_pad.wav")); continue
        if kind == "slide":
            still(os.path.join(SLIDES, src), dur, out)
        elif kind == "terminal":
            png = f"{W}/term.png"
            terminal_png(png)
            still(png, dur, out)
        else:
            frames, real = asyncio.run(record(kind, dur))
            if real > dur:   # recording longer than narration: speed it up evenly
                k = dur / real
                frames = [(p, t * k) for p, t in frames]
            frames_to_mp4(frames, dur, out)
        # narration padded to scene length
        aout = f"{W}/a{i:02d}_pad.wav"
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", f"{W}/a{i:02d}.wav", "-af", f"adelay=350|350,apad=whole_dur={dur:.3f}",
                        "-ar", "48000", "-ac", "2", aout], check=True)
        parts.append((out, aout))
    with open(f"{W}/v.txt", "w") as f:
        f.writelines(f"file '{v}'\n" for v, _ in parts)
    with open(f"{W}/a.txt", "w") as f:
        f.writelines(f"file '{a}'\n" for _, a in parts)
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0", "-i", f"{W}/v.txt", "-c", "copy", f"{W}/video.mp4"], check=True)
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0", "-i", f"{W}/a.txt", "-c:a", "pcm_s16le", f"{W}/audio.wav"], check=True)
    os.makedirs(os.path.join(ROOT, "presentation"), exist_ok=True)
    final = os.path.join(ROOT, "presentation", "Self_Healing_Cloud_Security_Demo.mp4")
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", f"{W}/video.mp4", "-i", f"{W}/audio.wav", "-map", "0:v", "-map", "1:a",
                    "-c:v", "copy", "-c:a", "aac", "-b:a", "160k", "-shortest", "-movflags", "+faststart", final + ".tmp.mp4"], check=True)
    os.replace(final + ".tmp.mp4", final)
    print("video ->", final)


if __name__ == "__main__":
    main()
