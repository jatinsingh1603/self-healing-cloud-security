import json
import os

import pytest

os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="us-east-1")

from moto import mock_aws  # noqa: E402

from selfheal import checks  # noqa: E402
from selfheal.decide import NoisySelector, validate  # noqa: E402
from selfheal.engine import Config, SelfHealer  # noqa: E402
from selfheal.faults import FaultyTools, StaleReads  # noqa: E402
from selfheal.guard import GuardedSession, PermissionDenied, reader_identity, remediator_identity  # noqa: E402
from selfheal.model import Rule, Status  # noqa: E402
from selfheal.scenarios import seed_controlled, seed_extra  # noqa: E402
from selfheal.tools import all_tool_actions  # noqa: E402


@pytest.fixture
def aws():
    with mock_aws():
        yield


def statuses(res):
    return {(o.finding.rule, o.finding.resource_id): o.status for o in res["outcomes"]}


def test_three_deck_scenarios_heal(aws):
    ids = seed_controlled()
    res = SelfHealer(config=Config(verify_backoff_s=0)).run()
    s = statuses(res)
    assert s[(Rule.S3_PUBLIC_ACCESS, ids["bucket"])] == Status.HEALED
    assert s[(Rule.SG_OPEN_SSH, ids["security_group"])] == Status.HEALED
    assert s[(Rule.CLOUDTRAIL_NOT_LOGGING, ids["trail"])] == Status.HEALED
    assert checks.scan(GuardedSession(reader_identity())) == []


def test_https_rule_is_kept(aws):
    ids = seed_controlled()
    SelfHealer(config=Config(verify_backoff_s=0)).run()
    import boto3
    sg = boto3.client("ec2").describe_security_groups(GroupIds=[ids["security_group"]])["SecurityGroups"][0]
    ports = {(p.get("FromPort")) for p in sg["IpPermissions"]}
    assert 443 in ports and 22 not in ports


def test_high_risk_needs_approval(aws):
    seed_extra()
    res = SelfHealer(config=Config(verify_backoff_s=0)).run()
    iam = [o for o in res["outcomes"] if o.finding.rule == Rule.IAM_ADMIN_WILDCARD]
    assert iam and all(o.status == Status.ESCALATED for o in iam)
    res2 = SelfHealer(config=Config(verify_backoff_s=0, approve_high_risk=True)).run()
    assert all(o.status == Status.HEALED for o in res2["outcomes"] if o.finding.rule == Rule.IAM_ADMIN_WILDCARD)


def test_missing_cloudtrail_is_created(aws):
    res = SelfHealer(config=Config(verify_backoff_s=0)).run()
    s = [o for o in res["outcomes"] if o.finding.rule == Rule.CLOUDTRAIL_MISSING]
    assert s and s[0].status == Status.HEALED


def test_guard_blocks_out_of_policy_calls(aws):
    g = GuardedSession(remediator_identity(all_tool_actions()))
    for svc, op, kw in [("s3", "delete_bucket", {"Bucket": "x"}), ("iam", "create_access_key", {"UserName": "x"}),
                        ("cloudtrail", "stop_logging", {"Name": "x"})]:
        with pytest.raises(PermissionDenied):
            getattr(g.client(svc), op)(**kw)


def test_verifier_is_read_only(aws):
    r = GuardedSession(reader_identity())
    with pytest.raises(PermissionDenied):
        r.client("s3").create_bucket(Bucket="nope")


def test_guardrail_rejects_wrong_and_invented_tools():
    from selfheal.model import Finding
    f = Finding(Rule.SG_OPEN_SSH, "security_group", "sg-1")
    assert validate(f, "fix_open_ssh")[0]
    assert not validate(f, "enable_s3_versioning")[0]
    assert not validate(f, "terminate_instances")[0]


def test_noisy_ai_never_runs_wrong_tool_with_guardrail(aws):
    seed_controlled(); seed_extra()
    res = SelfHealer(selector=NoisySelector(1.0, seed=3), config=Config(verify_backoff_s=0)).run()
    assert all(o.status in (Status.BLOCKED, Status.ESCALATED, Status.ALREADY_RESOLVED) for o in res["outcomes"])


def test_partial_fix_caught_and_retried(aws):
    seed_controlled()
    res = SelfHealer(config=Config(verify_backoff_s=0), tool_wrapper=FaultyTools(partial_p=1.0)).run()
    assert all(o.status == Status.HEALED and o.attempts == 2 for o in res["outcomes"])


def test_stale_reads_tolerated(aws):
    seed_controlled()
    res = SelfHealer(config=Config(verify_backoff_s=0, verify_retries=4), recheck_fn=StaleReads(2)).run()
    assert all(o.status == Status.HEALED for o in res["outcomes"])


def test_audit_log(aws, tmp_path):
    seed_controlled()
    p = tmp_path / "audit.jsonl"
    SelfHealer(config=Config(verify_backoff_s=0), audit_path=str(p)).run()
    rows = [json.loads(x) for x in p.read_text().splitlines()]
    assert len(rows) == 3 and all(r["status"] == "HEALED" and r["api_calls"] for r in rows)
