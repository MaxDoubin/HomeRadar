"""Unit tests for backend/pairing.py, exercised directly against a temp DB."""
from __future__ import annotations

from datetime import timedelta

from freezegun import freeze_time

from backend.db import models
from backend import pairing


def test_generate_code_is_six_digits():
    for _ in range(20):
        code = pairing.generate_code()
        assert len(code) == 6
        assert code.isdigit()


def test_issue_and_redeem_round_trip(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        issued = pairing.issue_pairing_code(conn)
        assert len(issued["code"]) == 6
        assert issued["expires_in"] == 600

        token = pairing.redeem_pairing_code(conn, issued["code"])
        assert token
        assert isinstance(token, str)


def test_redeeming_same_code_twice_fails_second_time(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        issued = pairing.issue_pairing_code(conn)
        first = pairing.redeem_pairing_code(conn, issued["code"])
        assert first is not None
        second = pairing.redeem_pairing_code(conn, issued["code"])
        assert second is None


def test_wrong_code_does_not_consume_real_outstanding_code(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        issued = pairing.issue_pairing_code(conn)
        wrong = "000000" if issued["code"] != "000000" else "111111"
        assert pairing.redeem_pairing_code(conn, wrong) is None
        # The real code should still be redeemable afterwards.
        token = pairing.redeem_pairing_code(conn, issued["code"])
        assert token is not None


def test_expired_code_fails_to_redeem(patched_db, db_path):
    with freeze_time("2026-01-01T00:00:00Z") as frozen:
        with models.get_conn(db_path) as conn:
            issued = pairing.issue_pairing_code(conn, ttl_seconds=60)
        frozen.tick(delta=timedelta(seconds=61))
        with models.get_conn(db_path) as conn:
            assert pairing.redeem_pairing_code(conn, issued["code"]) is None


def test_pairing_status_reflects_pending_and_expiry(patched_db, db_path):
    with freeze_time("2026-01-01T00:00:00Z") as frozen:
        with models.get_conn(db_path) as conn:
            assert pairing.pairing_status(conn) == {"pending": False, "expires_in": 0}
            pairing.issue_pairing_code(conn, ttl_seconds=100)
            status = pairing.pairing_status(conn)
            assert status["pending"] is True
            assert status["expires_in"] <= 100
        frozen.tick(delta=timedelta(seconds=101))
        with models.get_conn(db_path) as conn:
            assert pairing.pairing_status(conn) == {"pending": False, "expires_in": 0}


def test_get_or_create_token_is_idempotent(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        first = pairing.get_or_create_token(conn)
        second = pairing.get_or_create_token(conn)
        assert first == second


def test_verify_token_rejects_none_empty_and_wrong(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        token = pairing.get_or_create_token(conn)
        assert pairing.verify_token(conn, None) is False
        assert pairing.verify_token(conn, "") is False
        assert pairing.verify_token(conn, "definitely-wrong") is False
        assert pairing.verify_token(conn, token) is True


def test_regenerate_token_invalidates_old_token(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        old = pairing.get_or_create_token(conn)
        new = pairing.regenerate_token(conn)
        assert new != old
        assert pairing.verify_token(conn, old) is False
        assert pairing.verify_token(conn, new) is True


def test_lockout_after_five_failures_blocks_even_correct_code(patched_db, db_path):
    with freeze_time("2026-01-01T00:00:00Z") as frozen:
        with models.get_conn(db_path) as conn:
            issued = pairing.issue_pairing_code(conn, ttl_seconds=600)
            wrong = "000000" if issued["code"] != "000000" else "111111"
            for _ in range(5):
                assert pairing.redeem_pairing_code(conn, wrong) is None
            # Now locked out -- even the correct code fails.
            assert pairing.redeem_pairing_code(conn, issued["code"]) is None

        # Advance past the lockout window; the same still-outstanding code
        # (it was never consumed, since lockout blocks failures from ever
        # reaching the real comparison once triggered) should now work.
        frozen.tick(delta=timedelta(seconds=301))
        with models.get_conn(db_path) as conn:
            assert pairing.redeem_pairing_code(conn, issued["code"]) is not None
