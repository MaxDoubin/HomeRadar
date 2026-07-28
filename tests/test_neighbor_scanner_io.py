from __future__ import annotations

import subprocess

from backend.discovery import neighbor_scanner


def test_scan_uses_primary_command_and_skips_fallback(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n",
            stderr="",
        )

    monkeypatch.setattr(neighbor_scanner.subprocess, "run", fake_run)
    devices = neighbor_scanner.scan()
    assert devices == [
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF", "source": "neighbor_cache"}
    ]
    assert len(calls) == 1
    assert calls[0] == ("ip", "-4", "neigh", "show")


def test_scan_falls_back_when_primary_command_missing(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "ip":
            raise FileNotFoundError("no ip command")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="? (192.168.1.10) at b8:27:eb:00:00:01 on en0 ifscope [ethernet]\n",
            stderr="",
        )

    monkeypatch.setattr(neighbor_scanner.subprocess, "run", fake_run)
    devices = neighbor_scanner.scan()
    assert devices == [
        {"ip": "192.168.1.10", "mac": "B8:27:EB:00:00:01", "source": "neighbor_cache"}
    ]
    assert [c[0] for c in calls] == ["ip", "arp"]


def test_scan_returns_empty_when_both_commands_missing(monkeypatch):
    def fake_run(command, **kwargs):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(neighbor_scanner.subprocess, "run", fake_run)
    assert neighbor_scanner.scan() == []


def test_scan_falls_back_on_nonzero_exit_code(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "ip":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="ip: command failed")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="? (192.168.1.20) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n",
            stderr="",
        )

    monkeypatch.setattr(neighbor_scanner.subprocess, "run", fake_run)
    devices = neighbor_scanner.scan()
    assert devices == [
        {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66", "source": "neighbor_cache"}
    ]
    assert [c[0] for c in calls] == ["ip", "arp"]
