"""The closed control loop: Detect -> Decide -> Fix -> Verify.

    findings = detect()
    for each finding:
        if independent re-check says it is already gone   -> ALREADY_RESOLVED
        tool = selector.select(finding)
        if guardrail rejects tool                          -> BLOCKED (or safe fallback)
        if tool is HIGH risk and not approved              -> ESCALATED
        run tool through the least-privilege identity      (IAM deny -> BLOCKED)
        re-check with the separate read-only identity, with backoff
        if still present: retry once, else                 -> NOT_HEALED
        else                                               -> HEALED
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable

from . import checks
from .decide import RuleSelector, validate
from .guard import GuardedSession, PermissionDenied, reader_identity, remediator_identity
from .model import Finding, Outcome, Status
from .tools import TOOLS, all_tool_actions


@dataclass
class Config:
    guardrail: bool = True               # validate selector output against the registry
    fallback_to_rules: bool = False      # on a blocked AI choice, fall back to the rule selector
    verify: bool = True                  # independent re-check (switch off for ablation)
    approve_high_risk: bool = False      # human approval for HIGH risk tools
    max_fix_attempts: int = 2
    verify_retries: int = 4
    verify_backoff_s: float = 0.05
    dry_run: bool = False


@dataclass
class SelfHealer:
    region: str = "us-east-1"
    selector: object = field(default_factory=RuleSelector)
    config: Config = field(default_factory=Config)
    audit_path: str | None = None
    tool_wrapper: Callable | None = None            # fault injection hook (experiments)
    recheck_fn: Callable = checks.recheck           # fault injection hook (experiments)
    on_event: Callable | None = None                # live progress callback (demo UI)

    def __post_init__(self):
        self.reader = GuardedSession(reader_identity(), self.region)
        self.verifier = GuardedSession(reader_identity(), self.region)  # independent identity
        self.remediator = GuardedSession(remediator_identity(all_tool_actions()), self.region)
        self._audit = open(self.audit_path, "a") if self.audit_path else None

    # ---------------------------------------------------------------- stages
    def detect(self, rules=None) -> tuple[list[Finding], float]:
        t = time.perf_counter()
        f = checks.scan(self.reader, rules)
        return f, (time.perf_counter() - t) * 1000

    def _emit(self, kind, **kw):
        if self.on_event:
            self.on_event(kind, kw)

    def _log(self, outcome: Outcome):
        if self._audit:
            self._audit.write(json.dumps({"ts": time.time(), **outcome.to_dict()}) + "\n")
            self._audit.flush()

    def _verify(self, f: Finding) -> tuple[bool, float]:
        t = time.perf_counter()
        for i in range(self.config.verify_retries):
            if self.recheck_fn(self.verifier, f):
                return True, (time.perf_counter() - t) * 1000
            time.sleep(self.config.verify_backoff_s * (2 ** i))
        return False, (time.perf_counter() - t) * 1000

    def heal_one(self, f: Finding) -> Outcome:
        sel_name = getattr(self.selector, "name", type(self.selector).__name__)
        if checks.recheck(self.verifier, f):
            o = Outcome(f, None, sel_name, Status.ALREADY_RESOLVED, "cleared by an earlier fix in this run")
            self._log(o); return o

        t0 = time.perf_counter()
        try:
            tool_name = self.selector.select(f)
        except Exception as e:  # LLM outage etc. -> safe fallback
            tool_name = RuleSelector().select(f)
            sel_name += f"(fallback:{type(e).__name__})"
        t_decide = (time.perf_counter() - t0) * 1000
        self._emit("decide", finding=f.to_dict(), tool=tool_name)

        if self.config.guardrail:
            ok, why = validate(f, tool_name)
            if not ok:
                if self.config.fallback_to_rules:
                    tool_name = RuleSelector().select(f)
                    sel_name += "(guardrail-fallback)"
                else:
                    o = Outcome(f, tool_name, sel_name, Status.BLOCKED, f"guardrail: {why}", t_decide_ms=t_decide)
                    self._log(o); return o

        tool = TOOLS.get(tool_name)
        if tool is None:  # guardrail off and the AI invented a tool: nothing can run
            o = Outcome(f, tool_name, sel_name, Status.ERROR, "unknown tool executed with guardrail off", t_decide_ms=t_decide)
            self._log(o); return o

        if tool.risk == "HIGH" and not self.config.approve_high_risk:
            o = Outcome(f, tool_name, sel_name, Status.ESCALATED, "HIGH risk tool: waiting for human approval", t_decide_ms=t_decide)
            self._log(o); return o

        if self.config.dry_run:
            o = Outcome(f, tool_name, sel_name, Status.ESCALATED, "dry run: no change made", t_decide_ms=t_decide)
            self._log(o); return o

        run = self.tool_wrapper(tool) if self.tool_wrapper else tool.run
        attempts, t_fix, t_ver, detail, healed = 0, 0.0, 0.0, "", False
        start_calls = len(self.remediator.identity.calls)
        while attempts < self.config.max_fix_attempts and not healed:
            attempts += 1
            t1 = time.perf_counter()
            try:
                detail = run(self.remediator, f)
            except PermissionDenied as e:
                o = Outcome(f, tool_name, sel_name, Status.BLOCKED, f"IAM guard: {e}", attempts, t_decide, (time.perf_counter() - t1) * 1000)
                self._log(o); return o
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"
            t_fix += (time.perf_counter() - t1) * 1000
            self._emit("fix", finding=f.to_dict(), tool=tool_name, detail=detail, attempt=attempts)
            if not self.config.verify:
                healed = True  # trusts the API response: what we measure against
                break
            healed, tv = self._verify(f)
            t_ver += tv
        calls = self.remediator.identity.calls[start_calls:]
        status = Status.HEALED if healed else Status.NOT_HEALED
        o = Outcome(f, tool_name, sel_name, status, detail, attempts, t_decide, t_fix, t_ver, calls)
        self._emit("verify", finding=f.to_dict(), status=status.value)
        self._log(o)
        return o

    def run(self, rules=None) -> dict:
        findings, t_detect = self.detect(rules)
        self._emit("detect", count=len(findings), ms=t_detect)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: order[f.severity])   # broadest fix first
        outcomes = [self.heal_one(f) for f in findings]
        return {"t_detect_ms": t_detect, "findings": findings, "outcomes": outcomes}
