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


def test_parse_macos_arp_restores_dropped_leading_zeros():
    output = (
        "? (192.168.1.1) at 0:11:22:3:44:55 on en0 ifscope [ethernet]\n"
        "? (192.168.1.20) at a4:83:e7:b:c:d on en0 ifscope [ethernet]\n"
    )
    assert neighbor_scanner.parse_neighbor_output(output) == [
        {"ip": "192.168.1.1", "mac": "00:11:22:03:44:55", "source": "neighbor_cache"},
        {"ip": "192.168.1.20", "mac": "A4:83:E7:0B:0C:0D", "source": "neighbor_cache"},
    ]


def test_parse_windows_arp_table():
    output = (
        "\nInterface: 192.168.1.10 --- 0x4\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           00-11-22-33-44-55     dynamic\n"
        "  192.168.1.42          a4-83-e7-0b-0c-0d     dynamic\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
        "  224.0.0.22            01-00-5e-00-00-16     static\n"
    )
    assert neighbor_scanner.parse_neighbor_output(output) == [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "source": "neighbor_cache"},
        {"ip": "192.168.1.42", "mac": "A4:83:E7:0B:0C:0D", "source": "neighbor_cache"},
    ]


def test_parse_skips_incomplete_and_unusable_entries():
    output = (
        "? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]\n"
        "192.168.1.6 dev eth0  INCOMPLETE\n"
        "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
        "? (192.168.1.7) at 0:0:0:0:0:0 on en0 ifscope [ethernet]\n"
    )
    assert neighbor_scanner.parse_neighbor_output(output) == []


def test_parse_rejects_mac_with_extra_octets():
    output = "? (192.168.1.9) at 00:11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
    assert neighbor_scanner.parse_neighbor_output(output) == []
