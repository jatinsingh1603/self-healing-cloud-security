"""Fault injection for the 'stronger validation' experiments.

* StaleReads      - eventual consistency: the first k re-checks after a fix
                    still return the old state, as when an API call succeeds
                    before the resource settles.
* PartialFix      - with probability p the tool silently applies only part
                    of the change (e.g. 2 of 4 public-access settings, or
                    only the IPv4 half of an SG rule) but still reports success.
* TransientError  - with probability p the tool call throws (throttling).
"""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from . import checks
from .model import Rule


class StaleReads:
    def __init__(self, k: int):
        self.k = k
        self.seen: dict[str, int] = {}

    def __call__(self, session, finding) -> bool:
        n = self.seen.get(finding.key, 0)
        self.seen[finding.key] = n + 1
        if n < self.k:
            return False   # stale view: still looks broken
        return checks.recheck(session, finding)


class FaultyTools:
    def __init__(self, partial_p: float = 0.0, error_p: float = 0.0, seed: int = 0, first_attempt_only: bool = True):
        self.partial_p, self.error_p = partial_p, error_p
        self.rng = random.Random(seed)
        self.first_only = first_attempt_only
        self.attempts: dict[str, int] = {}
        self.injected = {"partial": 0, "error": 0}

    def __call__(self, tool):
        def run(sess, f):
            n = self.attempts.get(f.key, 0)
            self.attempts[f.key] = n + 1
            if self.first_only and n > 0:
                return tool.run(sess, f)
            r = self.rng.random()
            if r < self.error_p:
                self.injected["error"] += 1
                raise ClientError({"Error": {"Code": "Throttling", "Message": "Rate exceeded (injected)"}}, tool.name)
            if r < self.error_p + self.partial_p:
                self.injected["partial"] += 1
                return _partial(tool, sess, f)
            return tool.run(sess, f)
        return run


def _partial(tool, sess, f) -> str:
    """Do a believable but incomplete version of the fix and report success."""
    if f.rule == Rule.S3_PUBLIC_ACCESS:
        sess.client("s3").put_public_access_block(Bucket=f.resource_id, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
        return "public access block enabled (reported) [partial: 2/4]"
    # For every other rule: the API 'succeeds' but nothing is persisted.
    return f"{tool.name} returned 200 OK [partial: change not persisted]"
