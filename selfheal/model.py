"""Core data model shared by every stage of the self-healing loop."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Rule(str, Enum):
    """Misconfiguration rules the detector understands (CIS AWS aligned)."""
    S3_PUBLIC_ACCESS = "S3_PUBLIC_ACCESS"            # CIS 2.1.4
    S3_VERSIONING_DISABLED = "S3_VERSIONING_DISABLED"
    S3_NO_KMS_ENCRYPTION = "S3_NO_KMS_ENCRYPTION"    # CIS 2.1.1
    SG_OPEN_SSH = "SG_OPEN_SSH"                      # CIS 5.2
    SG_OPEN_RDP = "SG_OPEN_RDP"                      # CIS 5.2
    SG_OPEN_ALL_PORTS = "SG_OPEN_ALL_PORTS"          # CIS 5.2
    CLOUDTRAIL_MISSING = "CLOUDTRAIL_MISSING"        # CIS 3.1
    CLOUDTRAIL_NOT_LOGGING = "CLOUDTRAIL_NOT_LOGGING"
    CLOUDTRAIL_NOT_MULTI_REGION = "CLOUDTRAIL_NOT_MULTI_REGION"  # CIS 3.1
    CLOUDTRAIL_NO_LOG_VALIDATION = "CLOUDTRAIL_NO_LOG_VALIDATION"  # CIS 3.2
    IAM_ADMIN_WILDCARD = "IAM_ADMIN_WILDCARD"        # CIS 1.16


SEVERITY = {
    Rule.S3_PUBLIC_ACCESS: "HIGH",
    Rule.S3_VERSIONING_DISABLED: "LOW",
    Rule.S3_NO_KMS_ENCRYPTION: "MEDIUM",
    Rule.SG_OPEN_SSH: "HIGH",
    Rule.SG_OPEN_RDP: "HIGH",
    Rule.SG_OPEN_ALL_PORTS: "CRITICAL",
    Rule.CLOUDTRAIL_MISSING: "HIGH",
    Rule.CLOUDTRAIL_NOT_LOGGING: "HIGH",
    Rule.CLOUDTRAIL_NOT_MULTI_REGION: "MEDIUM",
    Rule.CLOUDTRAIL_NO_LOG_VALIDATION: "MEDIUM",
    Rule.IAM_ADMIN_WILDCARD: "CRITICAL",
}


class Status(str, Enum):
    HEALED = "HEALED"                    # fix applied and independent re-check passed
    NOT_HEALED = "NOT_HEALED"            # fix applied but re-check still sees the issue
    ESCALATED = "ESCALATED"              # high-risk tool, waiting for human approval
    BLOCKED = "BLOCKED"                  # guardrail refused the action (bad tool / IAM deny)
    ALREADY_RESOLVED = "ALREADY_RESOLVED"  # an earlier fix in this run already cleared it
    ERROR = "ERROR"


@dataclass
class Finding:
    rule: Rule
    resource_type: str          # s3_bucket | security_group | cloudtrail | iam_policy | account
    resource_id: str            # bucket name, sg id, trail name, policy arn
    evidence: dict[str, Any] = field(default_factory=dict)
    source_ref: str | None = None   # Terraform address the resource came from (datasets)

    @property
    def severity(self) -> str:
        return SEVERITY[self.rule]

    @property
    def key(self) -> str:
        return f"{self.rule.value}:{self.resource_id}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["rule"] = self.rule.value
        d["severity"] = self.severity
        return d


@dataclass
class Outcome:
    finding: Finding
    tool: str | None
    selector: str
    status: Status
    detail: str = ""
    attempts: int = 0
    t_decide_ms: float = 0.0
    t_fix_ms: float = 0.0
    t_verify_ms: float = 0.0
    api_calls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.to_dict(),
            "tool": self.tool,
            "selector": self.selector,
            "status": self.status.value,
            "detail": self.detail,
            "attempts": self.attempts,
            "t_decide_ms": round(self.t_decide_ms, 3),
            "t_fix_ms": round(self.t_fix_ms, 3),
            "t_verify_ms": round(self.t_verify_ms, 3),
            "api_calls": self.api_calls,
        }
