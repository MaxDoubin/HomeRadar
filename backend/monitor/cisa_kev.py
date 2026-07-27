"""CISA Known Exploited Vulnerabilities catalog synchronization.

The KEV catalog identifies actively exploited software vulnerabilities; it is not
an IP reputation list. Home Radar stores it locally so exposed device software can
be correlated against it as fingerprinting becomes more version-specific.
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone

from backend import config


def parse_catalog(payload: dict) -> list[dict]:
    records = []
    for item in payload.get("vulnerabilities", []):
        cve_id = str(item.get("cveID", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        records.append(
            {
                "cve_id": cve_id,
                "vendor_project": str(item.get("vendorProject", ""))[:200],
                "product": str(item.get("product", ""))[:200],
                "vulnerability_name": str(item.get("vulnerabilityName", ""))[:500],
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "ransomware_use": item.get("knownRansomwareCampaignUse"),
                "required_action": str(item.get("requiredAction", ""))[:1000],
            }
        )
    return records


def update_catalog(conn, url: str = config.CISA_KEV_URL, timeout: float = 30) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": "HomeRadar/0.2"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    records = parse_catalog(payload)
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        """INSERT INTO cisa_kev (
               cve_id, vendor_project, product, vulnerability_name, date_added,
               due_date, ransomware_use, required_action, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(cve_id) DO UPDATE SET
               vendor_project = excluded.vendor_project,
               product = excluded.product,
               vulnerability_name = excluded.vulnerability_name,
               date_added = excluded.date_added,
               due_date = excluded.due_date,
               ransomware_use = excluded.ransomware_use,
               required_action = excluded.required_action,
               updated_at = excluded.updated_at""",
        [
            (
                item["cve_id"],
                item["vendor_project"],
                item["product"],
                item["vulnerability_name"],
                item["date_added"],
                item["due_date"],
                item["ransomware_use"],
                item["required_action"],
                now,
            )
            for item in records
        ],
    )
    return len(records)


def search_catalog(conn, query: str = "", limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    if query:
        pattern = f"%{query}%"
        rows = conn.execute(
            """SELECT * FROM cisa_kev
               WHERE cve_id LIKE ? OR vendor_project LIKE ? OR product LIKE ?
                    OR vulnerability_name LIKE ?
               ORDER BY date_added DESC LIMIT ?""",
            (pattern, pattern, pattern, pattern, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM cisa_kev ORDER BY date_added DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]
