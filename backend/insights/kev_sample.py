"""A small, verbatim excerpt of CISA's Known Exploited Vulnerabilities catalog.

Used only by demo mode, and only when the real catalog has never been
downloaded, so the vulnerability check has something to show offline. Every
field is copied exactly from the public catalog (catalogVersion 2026.10.23,
https://www.cisa.gov/known-exploited-vulnerabilities-catalog); nothing here is
invented. A real catalog update overwrites these rows with the same data.
"""
from __future__ import annotations

_MITIGATE = (
    "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for "
    "cloud services, or discontinue use of the product if mitigations are unavailable."
)

KEV_SAMPLE: tuple[dict, ...] = (
    {
        "cve_id": "CVE-2017-5521",
        "vendor_project": "NETGEAR",
        "product": "Multiple Devices",
        "vulnerability_name": "NETGEAR Multiple Devices Exposure of Sensitive Information Vulnerability",
        "date_added": "2022-09-08",
        "due_date": "2022-09-29",
        "ransomware_use": "Unknown",
        "required_action": (
            "Apply updates per vendor instructions. If the affected device has since entered "
            "end-of-life, it should be disconnected if still in use."
        ),
    },
    {
        "cve_id": "CVE-2017-6862",
        "vendor_project": "NETGEAR",
        "product": "Multiple Devices",
        "vulnerability_name": "NETGEAR Multiple Devices Buffer Overflow Vulnerability",
        "date_added": "2022-06-08",
        "due_date": "2022-06-22",
        "ransomware_use": "Unknown",
        "required_action": "Apply updates per vendor instructions.",
    },
    {
        "cve_id": "CVE-2023-50224",
        "vendor_project": "TP-Link",
        "product": "TL-WR841N",
        "vulnerability_name": "TP-Link TL-WR841N Authentication Bypass by Spoofing Vulnerability",
        "date_added": "2025-09-03",
        "due_date": "2025-09-24",
        "ransomware_use": "Unknown",
        "required_action": _MITIGATE,
    },
    {
        "cve_id": "CVE-2025-9377",
        "vendor_project": "TP-Link",
        "product": "Multiple Routers",
        "vulnerability_name": "TP-Link Archer C7(EU) and TL-WR841N/ND(MS) OS Command Injection Vulnerability",
        "date_added": "2025-09-03",
        "due_date": "2025-09-24",
        "ransomware_use": "Unknown",
        "required_action": _MITIGATE,
    },
    {
        "cve_id": "CVE-2025-29635",
        "vendor_project": "D-Link",
        "product": "DIR-823X",
        "vulnerability_name": "D-Link DIR-823X Command Injection Vulnerability",
        "date_added": "2026-04-24",
        "due_date": "2026-05-08",
        "ransomware_use": "Unknown",
        "required_action": _MITIGATE,
    },
    {
        "cve_id": "CVE-2022-37055",
        "vendor_project": "D-Link",
        "product": "Routers",
        "vulnerability_name": "D-Link Routers Buffer Overflow Vulnerability",
        "date_added": "2025-12-08",
        "due_date": "2025-12-29",
        "ransomware_use": "Unknown",
        "required_action": _MITIGATE,
    },
    {
        "cve_id": "CVE-2025-59374",
        "vendor_project": "ASUS",
        "product": "Live Update",
        "vulnerability_name": "ASUS Live Update Embedded Malicious Code Vulnerability",
        "date_added": "2025-12-17",
        "due_date": "2026-01-07",
        "ransomware_use": "Unknown",
        "required_action": _MITIGATE,
    },
    {
        "cve_id": "CVE-2021-32030",
        "vendor_project": "ASUS",
        "product": "Routers",
        "vulnerability_name": "ASUS Routers Improper Authentication Vulnerability",
        "date_added": "2025-06-02",
        "due_date": "2025-06-23",
        "ransomware_use": "Unknown",
        "required_action": _MITIGATE,
    },
)
