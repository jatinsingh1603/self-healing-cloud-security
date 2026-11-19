"""Least-privilege guard.

Every boto3 client handed to a remediation tool is wrapped so that each API
call is checked against an IAM-style allow list *before* it leaves the
process. This mirrors the restricted IAM identity from the design (the same
policy is exported to iam/remediator-policy.json for real AWS) and gives a
second, local layer of defence if the cloud-side policy is ever too broad.

The verifier uses a separate read-only identity, so the component that
judges "healed" can never change the resource it is judging.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field

import boto3

# boto3 service name -> IAM action prefix
_PREFIX = {"s3": "s3", "ec2": "ec2", "cloudtrail": "cloudtrail", "iam": "iam", "sts": "sts"}

# botocore operation names that map to a different IAM action name
_ACTION_ALIASES = {
    "s3:PutBucketEncryption": "s3:PutEncryptionConfiguration",
    "s3:GetBucketEncryption": "s3:GetEncryptionConfiguration",
    "s3:PutPublicAccessBlock": "s3:PutBucketPublicAccessBlock",
    "s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
    "s3:HeadBucket": "s3:ListBucket",
    "s3:GetBucketPolicyStatus": "s3:GetBucketPolicyStatus",
}

READ_ONLY_PATTERNS = ["*:Get*", "*:List*", "*:Describe*", "*:Head*", "sts:GetCallerIdentity"]


class PermissionDenied(Exception):
    """Raised when a tool attempts an API call outside its granted policy."""


@dataclass
class Identity:
    name: str
    allow: list[str]
    calls: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)

    def permits(self, action: str) -> bool:
        return any(fnmatch.fnmatchcase(action, p) for p in self.allow)

    def policy_document(self) -> dict:
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": f"{self.name}Allow",
                "Effect": "Allow",
                "Action": sorted(set(self.allow)),
                "Resource": "*",
            }],
        }


def iam_action(service: str, operation: str) -> str:
    action = f"{_PREFIX.get(service, service)}:{operation}"
    return _ACTION_ALIASES.get(action, action)


class GuardedSession:
    """Creates boto3 clients whose calls are checked against an Identity."""

    def __init__(self, identity: Identity, region: str = "us-east-1", session: boto3.Session | None = None):
        self.identity = identity
        self.region = region
        self._session = session or boto3.Session(region_name=region)
        self._clients: dict[str, object] = {}

    def client(self, service: str):
        if service not in self._clients:
            c = self._session.client(service, region_name=self.region)
            c.meta.events.register("before-call.*.*", self._check)
            self._clients[service] = c
        return self._clients[service]

    def _check(self, model, **_):
        action = iam_action(model.service_model.service_name, model.name)
        if not self.identity.permits(action):
            self.identity.denied.append(action)
            raise PermissionDenied(f"{self.identity.name} is not allowed to call {action}")
        self.identity.calls.append(action)


def reader_identity() -> Identity:
    return Identity("SelfHealReader", list(READ_ONLY_PATTERNS))


def remediator_identity(tool_actions: list[str]) -> Identity:
    """Least privilege: only the write actions the approved tools need, plus reads."""
    return Identity("SelfHealRemediator", sorted(set(tool_actions)) + list(READ_ONLY_PATTERNS))


def export_policy(identity: Identity, path: str) -> None:
    with open(path, "w") as f:
        json.dump(identity.policy_document(), f, indent=2)
