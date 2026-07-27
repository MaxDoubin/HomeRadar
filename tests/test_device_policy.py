from datetime import datetime

from backend.dns.policy import evaluate_policy


def test_device_policy_pauses_internet_and_matches_parent_domains():
    assert evaluate_policy({"internet_enabled": False}, "example.com").blocked
    policy = {
        "internet_enabled": True,
        "blocked_domains": ["social.example"],
        "allowed_domains": [],
    }
    decision = evaluate_policy(policy, "video.social.example")
    assert decision.blocked
    assert decision.reason == "custom device domain rule"


def test_allow_rule_overrides_custom_block_and_overnight_schedule():
    policy = {
        "internet_enabled": True,
        "blocked_domains": ["example.com"],
        "allowed_domains": ["school.example.com"],
        "block_start": "21:00",
        "block_end": "07:00",
    }
    assert not evaluate_policy(policy, "school.example.com", datetime(2026, 1, 1, 12)).blocked
    assert evaluate_policy(policy, "other.test", datetime(2026, 1, 1, 23)).blocked
    assert not evaluate_policy(policy, "other.test", datetime(2026, 1, 1, 12)).blocked
