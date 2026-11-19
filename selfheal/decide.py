"""Decide stage: choose ONE approved tool for a finding.

Three selectors share one interface, `select(finding) -> str`:

* RuleSelector  - fixed mapping, the baseline the deck compares against.
* LLMSelector   - asks an LLM (Anthropic, any OpenAI-compatible endpoint,
                  or an n8n AI-agent webhook) to pick from the tool catalogue.
* NoisySelector - experiment harness that simulates an unreliable AI by
                  returning a wrong or invented tool with probability p.

Whatever the selector says, `validate()` is the guardrail: the tool must exist
in the registry AND be approved for that finding's rule.
"""
from __future__ import annotations

import json
import os
import random
import re
import urllib.request

from .model import Finding
from .tools import ALLOWED_FOR, TOOLS


class RuleSelector:
    name = "rule"

    def select(self, f: Finding) -> str:
        return sorted(ALLOWED_FOR[f.rule])[0]


def catalogue() -> str:
    return "\n".join(f"- {t.name} (risk {t.risk}): {t.description}" for t in TOOLS.values())


PROMPT = """You are the decision step of a cloud self-healing system.
Pick exactly ONE remediation tool from the approved list for the finding below.
Reply with JSON only: {{"tool": "<name>", "reason": "<one sentence>"}}.
If no tool fits, reply {{"tool": "none", "reason": "..."}}.

Approved tools:
{tools}

Finding:
{finding}
"""


class LLMSelector:
    """Provider-agnostic LLM selector.

    SELFHEAL_LLM=anthropic  uses ANTHROPIC_API_KEY (model SELFHEAL_MODEL)
    SELFHEAL_LLM=openai     uses OPENAI_API_KEY / OPENAI_BASE_URL (any compatible server, e.g. Ollama)
    SELFHEAL_LLM=n8n        POSTs to SELFHEAL_N8N_WEBHOOK, expects {"tool": ...}
    """
    name = "llm"

    def __init__(self, provider: str | None = None, timeout: float = 30):
        self.provider = provider or os.environ.get("SELFHEAL_LLM", "anthropic")
        self.timeout = timeout
        self.last_reason = ""

    def _post(self, url, body, headers):
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    def select(self, f: Finding) -> str:
        prompt = PROMPT.format(tools=catalogue(), finding=json.dumps(f.to_dict(), default=str))
        if self.provider == "anthropic":
            r = self._post("https://api.anthropic.com/v1/messages", {
                "model": os.environ.get("SELFHEAL_MODEL", "claude-haiku-5-5"), "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}]},
                {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"})
            text = r["content"][0]["text"]
        elif self.provider == "openai":
            base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            r = self._post(f"{base}/chat/completions", {
                "model": os.environ.get("SELFHEAL_MODEL", "gpt-4o-mini"),
                "messages": [{"role": "user", "content": prompt}], "temperature": 0},
                {"authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}"})
            text = r["choices"][0]["message"]["content"]
        elif self.provider == "n8n":
            r = self._post(os.environ["SELFHEAL_N8N_WEBHOOK"], {"finding": f.to_dict(), "tools": list(TOOLS)}, {})
            text = json.dumps(r)
        else:
            raise ValueError(self.provider)
        m = re.search(r"\{.*\}", text, re.S)
        data = json.loads(m.group(0)) if m else {"tool": text.strip()}
        self.last_reason = data.get("reason", "")
        return str(data.get("tool", "none"))


class NoisySelector:
    """Simulated imperfect AI for robustness experiments."""

    def __init__(self, error_rate: float, seed: int = 0):
        self.error_rate = error_rate
        self.rng = random.Random(seed)
        self.name = f"noisy-ai@{int(error_rate * 100)}%"
        self._base = RuleSelector()

    def select(self, f: Finding) -> str:
        if self.rng.random() >= self.error_rate:
            return self._base.select(f)
        if self.rng.random() < 0.3:   # hallucinated tool name
            return self.rng.choice(["delete_bucket", "terminate_instances", "disable_guardduty", "fix_everything"])
        wrong = [t for t in TOOLS if t not in ALLOWED_FOR[f.rule]]
        return self.rng.choice(wrong)


def validate(f: Finding, tool: str) -> tuple[bool, str]:
    if tool not in TOOLS:
        return False, f"'{tool}' is not an approved tool"
    if tool not in ALLOWED_FOR[f.rule]:
        return False, f"'{tool}' is approved but not for rule {f.rule.value}"
    return True, "ok"
