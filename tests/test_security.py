"""Security-boundary regression tests for LAN and appliance-local access."""
from backend.security import (
    authorization_decision,
    extract_presented_token,
    is_local_host,
    path_requires_auth,
)


def test_loopback_detection_does_not_trust_private_lan_addresses():
    assert is_local_host("127.0.0.1")
    assert is_local_host("::1")
    assert is_local_host("localhost")
    assert is_local_host("testclient")
    assert not is_local_host("192.168.1.50")
    assert not is_local_host("10.0.0.8")
    assert not is_local_host("homeradar.local")
    assert not is_local_host(None)


def test_token_extraction_supports_header_bearer_and_cookie():
    assert extract_presented_token({"x-homeradar-token": "direct"}) == "direct"
    assert extract_presented_token({"authorization": "Bearer bearer-token"}) == "bearer-token"
    assert extract_presented_token({}, {"homeradar_token": "cookie-token"}) == "cookie-token"
    assert extract_presented_token({}) is None


def test_sensitive_reads_require_authentication():
    for path in (
        "/dashboard",
        "/devices",
        "/alerts",
        "/traffic",
        "/settings",
        "/backups",
        "/digest/preview",
        "/pair/local-token",
    ):
        assert path_requires_auth(path)


def test_health_and_pair_claim_remain_public():
    for path in ("/status", "/health", "/pair/claim"):
        assert not path_requires_auth(path)


def test_remote_clients_need_valid_token_for_dashboard():
    assert authorization_decision("/dashboard", local=False, token_valid=False) == (False, 401)
    assert authorization_decision("/dashboard", local=False, token_valid=True) == (True, 200)


def test_local_token_never_leaves_loopback():
    assert authorization_decision("/pair/local-token", local=False, token_valid=True) == (False, 403)
    assert authorization_decision("/pair/local-token", local=True, token_valid=False) == (True, 200)


def test_setup_and_pair_code_generation_allow_local_or_paired_clients():
    for path in ("/setup", "/pair/start"):
        assert authorization_decision(path, local=False, token_valid=False) == (False, 403)
        assert authorization_decision(path, local=True, token_valid=False) == (True, 200)
        assert authorization_decision(path, local=False, token_valid=True) == (True, 200)
