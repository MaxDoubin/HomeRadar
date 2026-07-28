import ssl

import pytest

from backend import config
from backend.alerts.email_digest import build_digest, send_digest
from backend.db import models


def test_build_digest_with_seeded_device_and_alert(db_path):
    with models.get_conn(db_path) as conn:
        models.upsert_device(
            conn,
            "AA:BB:CC:DD:EE:01",
            "192.168.1.20",
            "kitchen-cam",
            "Acme Corp",
            device_type="camera",
        )
        models.create_alert(
            conn,
            None,
            "warning",
            "Suspicious connection: 6.6.6.6",
            "Something bad happened",
        )
        subject, body = build_digest(conn)

    assert "security score" in subject
    assert config.HOUSEHOLD_NAME in subject or "Home" in subject
    assert "New devices: 1" in body
    assert "kitchen-cam" in body
    assert "192.168.1.20" in body
    assert "camera" in body
    assert "[WARNING] Suspicious connection: 6.6.6.6" in body
    assert "Something bad happened" in body


def test_build_digest_with_nothing_seeded_uses_fallback_text(db_path):
    with models.get_conn(db_path) as conn:
        subject, body = build_digest(conn)

    assert "New devices: 0" in body
    lines = body.splitlines()
    new_devices_idx = lines.index("New devices")
    assert lines[new_devices_idx + 2] == "- None"
    alerts_idx = lines.index("Recent alerts")
    assert lines[alerts_idx + 2] == "- None"
    # Healthy network (no alerts, no devices) -> perfect score, "keep updated" message.
    assert "security score 100" in subject
    assert "Your network looks healthy" in body


def test_send_digest_raises_when_smtp_unconfigured(monkeypatch, db_path):
    monkeypatch.setattr(config, "SMTP_HOST", "")
    monkeypatch.setattr(config, "SMTP_FROM", "")
    monkeypatch.setattr(config, "SMTP_TO", "")
    with models.get_conn(db_path) as conn:
        with pytest.raises(RuntimeError):
            send_digest(conn)


def test_send_digest_raises_when_recipient_missing_even_if_host_and_from_set(
    monkeypatch, db_path
):
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_FROM", "alerts@example.com")
    monkeypatch.setattr(config, "SMTP_TO", "")
    with models.get_conn(db_path) as conn:
        with pytest.raises(RuntimeError):
            send_digest(conn, recipient=None)


def _configure_smtp(monkeypatch, **overrides):
    defaults = dict(
        SMTP_HOST="smtp.example.com",
        SMTP_PORT=587,
        SMTP_FROM="alerts@example.com",
        SMTP_TO="owner@example.com",
        SMTP_USERNAME="",
        SMTP_PASSWORD="",
        SMTP_USE_TLS=True,
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        monkeypatch.setattr(config, key, value)


def test_send_digest_full_flow_uses_tls_and_login_when_configured(
    monkeypatch, db_path, smtp_mock
):
    factory, instance = smtp_mock
    _configure_smtp(
        monkeypatch,
        SMTP_USERNAME="smtpuser",
        SMTP_PASSWORD="smtppass",
        SMTP_USE_TLS=True,
    )
    monkeypatch.setattr("backend.alerts.email_digest.smtplib.SMTP", factory)

    with models.get_conn(db_path) as conn:
        result = send_digest(conn)

    assert result["sent"] is True
    assert result["recipient"] == "owner@example.com"

    factory.assert_called_once_with("smtp.example.com", 587, timeout=20)
    instance.starttls.assert_called_once()
    _, starttls_kwargs = instance.starttls.call_args
    assert isinstance(starttls_kwargs["context"], ssl.SSLContext)
    instance.login.assert_called_once_with("smtpuser", "smtppass")
    instance.send_message.assert_called_once()
    (sent_message,) = instance.send_message.call_args[0]
    assert sent_message["From"] == "alerts@example.com"
    assert sent_message["To"] == "owner@example.com"
    assert sent_message["Subject"] == result["subject"]


def test_send_digest_skips_tls_when_disabled(monkeypatch, db_path, smtp_mock):
    factory, instance = smtp_mock
    _configure_smtp(
        monkeypatch,
        SMTP_USERNAME="smtpuser",
        SMTP_PASSWORD="smtppass",
        SMTP_USE_TLS=False,
    )
    monkeypatch.setattr("backend.alerts.email_digest.smtplib.SMTP", factory)

    with models.get_conn(db_path) as conn:
        send_digest(conn)

    instance.starttls.assert_not_called()
    instance.login.assert_called_once_with("smtpuser", "smtppass")
    instance.send_message.assert_called_once()


def test_send_digest_skips_login_when_no_username_configured(
    monkeypatch, db_path, smtp_mock
):
    factory, instance = smtp_mock
    _configure_smtp(monkeypatch, SMTP_USERNAME="", SMTP_PASSWORD="", SMTP_USE_TLS=True)
    monkeypatch.setattr("backend.alerts.email_digest.smtplib.SMTP", factory)

    with models.get_conn(db_path) as conn:
        send_digest(conn)

    instance.starttls.assert_called_once()
    instance.login.assert_not_called()
    instance.send_message.assert_called_once()


def test_send_digest_recipient_falls_back_to_config_smtp_to(
    monkeypatch, db_path, smtp_mock
):
    factory, instance = smtp_mock
    _configure_smtp(monkeypatch, SMTP_TO="fallback@example.com")
    monkeypatch.setattr("backend.alerts.email_digest.smtplib.SMTP", factory)

    with models.get_conn(db_path) as conn:
        result = send_digest(conn, recipient=None)

    assert result["recipient"] == "fallback@example.com"
    (sent_message,) = instance.send_message.call_args[0]
    assert sent_message["To"] == "fallback@example.com"


def test_send_digest_explicit_recipient_overrides_config(monkeypatch, db_path, smtp_mock):
    factory, instance = smtp_mock
    _configure_smtp(monkeypatch, SMTP_TO="fallback@example.com")
    monkeypatch.setattr("backend.alerts.email_digest.smtplib.SMTP", factory)

    with models.get_conn(db_path) as conn:
        result = send_digest(conn, recipient="explicit@example.com")

    assert result["recipient"] == "explicit@example.com"
