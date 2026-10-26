"""'Who's tracking you?': map a household's DNS lookups to known tracking companies.

Every DNS lookup the proxy answers is stored in ``traffic_logs`` (``domain``,
``device_id``, ``was_blocked``, ``created_at``). This module matches those
domains against a small, curated table of well-known advertising, analytics,
telemetry, and smart-TV viewing-data (automatic content recognition, "ACR")
endpoints and summarizes which companies each device talked to.

The table is deliberately conservative. Entries are the long-standing, widely
documented collection hosts of each company, the same domains that appear in
the major public privacy blocklists (EasyPrivacy, Disconnect's tracker list,
the Steven Black and OISD hosts lists) and in the companies' own SDK and
tag documentation. Domains that mostly serve a product's own content (for
example a streaming service's video CDN or an app's main API) are left out on
purpose, so a match means "this lookup goes to a data-collection or ad
endpoint", never "this device is compromised". A domain matches an entry
when it equals the entry or is a subdomain of it.
"""
from __future__ import annotations

from collections import defaultdict

from backend.insights import device_display_name

ADVERTISING = "Advertising"
ANALYTICS = "Analytics"
TELEMETRY = "Device telemetry"
TV_VIEWING = "TV viewing data"
SOCIAL = "Social media tracking"

# domain suffix -> (company, category)
TRACKERS: dict[str, tuple[str, str]] = {
    # Google
    "doubleclick.net": ("Google", ADVERTISING),
    "googlesyndication.com": ("Google", ADVERTISING),
    "googleadservices.com": ("Google", ADVERTISING),
    "googletagservices.com": ("Google", ADVERTISING),
    "adservice.google.com": ("Google", ADVERTISING),
    "2mdn.net": ("Google", ADVERTISING),
    "admob.com": ("Google", ADVERTISING),
    "google-analytics.com": ("Google", ANALYTICS),
    "googletagmanager.com": ("Google", ANALYTICS),
    "app-measurement.com": ("Google", ANALYTICS),
    "firebaselogging.googleapis.com": ("Google", TELEMETRY),
    "firebaselogging-pa.googleapis.com": ("Google", TELEMETRY),
    "crashlytics.com": ("Google", TELEMETRY),
    # Meta
    "facebook.net": ("Meta", SOCIAL),
    "graph.facebook.com": ("Meta", SOCIAL),
    "an.facebook.com": ("Meta", ADVERTISING),
    "pixel.facebook.com": ("Meta", ADVERTISING),
    # Amazon
    "amazon-adsystem.com": ("Amazon", ADVERTISING),
    "device-metrics-us.amazon.com": ("Amazon", TELEMETRY),
    "device-metrics-us-2.amazon.com": ("Amazon", TELEMETRY),
    "unagi.amazon.com": ("Amazon", TELEMETRY),
    "unagi-na.amazon.com": ("Amazon", TELEMETRY),
    # Microsoft
    "events.data.microsoft.com": ("Microsoft", TELEMETRY),
    "vortex.data.microsoft.com": ("Microsoft", TELEMETRY),
    "telemetry.microsoft.com": ("Microsoft", TELEMETRY),
    "bat.bing.com": ("Microsoft", ADVERTISING),
    "clarity.ms": ("Microsoft", ANALYTICS),
    "adnxs.com": ("Xandr (Microsoft)", ADVERTISING),
    # Apple
    "iadsdk.apple.com": ("Apple", ADVERTISING),
    "xp.apple.com": ("Apple", TELEMETRY),
    "metrics.icloud.com": ("Apple", TELEMETRY),
    # Smart TVs and streaming boxes
    "samsungads.com": ("Samsung", ADVERTISING),
    "samsungadhub.com": ("Samsung", ADVERTISING),
    "samsungacr.com": ("Samsung", TV_VIEWING),
    "lgsmartad.com": ("LG", ADVERTISING),
    "alphonso.tv": ("LG (Alphonso)", TV_VIEWING),
    "tvinteractive.tv": ("Vizio (Inscape)", TV_VIEWING),
    "samba.tv": ("Samba TV", TV_VIEWING),
    "ads.roku.com": ("Roku", ADVERTISING),
    "logs.roku.com": ("Roku", TELEMETRY),
    "ichnaea.netflix.com": ("Netflix", TELEMETRY),
    # Phone and tablet makers
    "tracking.miui.com": ("Xiaomi", TELEMETRY),
    "mistat.xiaomi.com": ("Xiaomi", TELEMETRY),
    "metrics.data.hicloud.com": ("Huawei", TELEMETRY),
    # Social networks
    "ads-twitter.com": ("X (Twitter)", ADVERTISING),
    "analytics.twitter.com": ("X (Twitter)", ANALYTICS),
    "analytics.tiktok.com": ("TikTok", ANALYTICS),
    "ads.tiktok.com": ("TikTok", ADVERTISING),
    "log.byteoversea.com": ("TikTok", TELEMETRY),
    "tr.snapchat.com": ("Snap", ADVERTISING),
    "ct.pinterest.com": ("Pinterest", ADVERTISING),
    "px.ads.linkedin.com": ("LinkedIn", ADVERTISING),
    "snap.licdn.com": ("LinkedIn", ANALYTICS),
    # Yahoo
    "ads.yahoo.com": ("Yahoo", ADVERTISING),
    "analytics.yahoo.com": ("Yahoo", ANALYTICS),
    "flurry.com": ("Yahoo (Flurry)", ANALYTICS),
    # Ad exchanges and ad tech
    "adsrvr.org": ("The Trade Desk", ADVERTISING),
    "rubiconproject.com": ("Magnite", ADVERTISING),
    "pubmatic.com": ("PubMatic", ADVERTISING),
    "openx.net": ("OpenX", ADVERTISING),
    "casalemedia.com": ("Index Exchange", ADVERTISING),
    "criteo.com": ("Criteo", ADVERTISING),
    "criteo.net": ("Criteo", ADVERTISING),
    "taboola.com": ("Taboola", ADVERTISING),
    "outbrain.com": ("Outbrain", ADVERTISING),
    "bidswitch.net": ("Bidswitch", ADVERTISING),
    "moatads.com": ("Oracle (Moat)", ADVERTISING),
    "bluekai.com": ("Oracle (BlueKai)", ADVERTISING),
    "doubleverify.com": ("DoubleVerify", ADVERTISING),
    "adsafeprotected.com": ("Integral Ad Science", ADVERTISING),
    "crwdcntrl.net": ("Lotame", ADVERTISING),
    "rlcdn.com": ("LiveRamp", ADVERTISING),
    "demdex.net": ("Adobe", ADVERTISING),
    "everesttech.net": ("Adobe", ADVERTISING),
    "omtrdc.net": ("Adobe", ANALYTICS),
    "2o7.net": ("Adobe", ANALYTICS),
    "quantserve.com": ("Quantcast", ADVERTISING),
    "quantcount.com": ("Quantcast", ANALYTICS),
    # In-app ad networks (common in kids' games)
    "applovin.com": ("AppLovin", ADVERTISING),
    "applvn.com": ("AppLovin", ADVERTISING),
    "mopub.com": ("MoPub", ADVERTISING),
    "unityads.unity3d.com": ("Unity Ads", ADVERTISING),
    "supersonicads.com": ("ironSource", ADVERTISING),
    "vungle.com": ("Vungle", ADVERTISING),
    "chartboost.com": ("Chartboost", ADVERTISING),
    "inmobi.com": ("InMobi", ADVERTISING),
    "smaato.net": ("Smaato", ADVERTISING),
    # Mobile attribution and product analytics
    "appsflyer.com": ("AppsFlyer", ANALYTICS),
    "appsflyersdk.com": ("AppsFlyer", ANALYTICS),
    "branch.io": ("Branch", ANALYTICS),
    "adjust.com": ("Adjust", ANALYTICS),
    "kochava.com": ("Kochava", ANALYTICS),
    "braze.com": ("Braze", ANALYTICS),
    "mixpanel.com": ("Mixpanel", ANALYTICS),
    "segment.io": ("Segment", ANALYTICS),
    "amplitude.com": ("Amplitude", ANALYTICS),
    "heapanalytics.com": ("Heap", ANALYTICS),
    "hotjar.com": ("Hotjar", ANALYTICS),
    "fullstory.com": ("FullStory", ANALYTICS),
    "crazyegg.com": ("Crazy Egg", ANALYTICS),
    "optimizely.com": ("Optimizely", ANALYTICS),
    "chartbeat.com": ("Chartbeat", ANALYTICS),
    "chartbeat.net": ("Chartbeat", ANALYTICS),
    "tiqcdn.com": ("Tealium", ANALYTICS),
    "go-mpulse.net": ("Akamai", ANALYTICS),
    "scorecardresearch.com": ("Comscore", ANALYTICS),
    "imrworldwide.com": ("Nielsen", ANALYTICS),
    "mc.yandex.ru": ("Yandex", ANALYTICS),
    "hm.baidu.com": ("Baidu", ANALYTICS),
    # Crash and performance reporting
    "nr-data.net": ("New Relic", TELEMETRY),
    "sentry.io": ("Sentry", TELEMETRY),
    "bugsnag.com": ("Bugsnag", TELEMETRY),
}


def match_tracker(domain: str | None) -> tuple[str, str] | None:
    """Return ``(company, category)`` when ``domain`` is a known tracking host."""
    if not domain:
        return None
    labels = domain.strip().strip(".").lower().split(".")
    for index in range(len(labels) - 1):
        hit = TRACKERS.get(".".join(labels[index:]))
        if hit:
            return hit
    return None


def _clamp_hours(hours: int) -> int:
    return max(1, min(int(hours), 24 * 30))


def _domain_counts(conn, hours: int, device_id: int | None = None) -> list[dict]:
    query = """SELECT device_id, domain, COUNT(*) AS requests,
                      COALESCE(SUM(was_blocked), 0) AS blocked
               FROM traffic_logs
               WHERE domain IS NOT NULL
                 AND julianday(created_at) >= julianday('now', ?)"""
    params: list = [f"-{_clamp_hours(hours)} hours"]
    if device_id is not None:
        query += " AND device_id = ?"
        params.append(device_id)
    query += " GROUP BY device_id, domain"
    return [dict(row) for row in conn.execute(query, params).fetchall()]


def _summarize(rows: list[dict]) -> dict:
    """Fold per-domain counts into per-company totals for one device."""
    companies: dict[str, dict] = {}
    tracker_requests = blocked = dns_queries = 0
    for row in rows:
        dns_queries += row["requests"]
        hit = match_tracker(row["domain"])
        if not hit:
            continue
        company, category = hit
        entry = companies.setdefault(
            company,
            {"company": company, "requests": 0, "blocked": 0, "domains": [], "by_category": {}},
        )
        entry["by_category"][category] = entry["by_category"].get(category, 0) + row["requests"]
        entry["requests"] += row["requests"]
        entry["blocked"] += row["blocked"]
        entry["domains"].append(row["domain"])
        tracker_requests += row["requests"]
        blocked += row["blocked"]
    ordered = sorted(companies.values(), key=lambda item: (-item["requests"], item["company"]))
    for entry in ordered:
        entry["domains"] = sorted(set(entry["domains"]))[:5]
        by_category = entry.pop("by_category")
        ranked = sorted(by_category, key=lambda name: (-by_category[name], name))
        entry["category"] = ranked[0]
        entry["categories"] = ranked
    return {
        "dns_queries": dns_queries,
        "tracker_requests": tracker_requests,
        "blocked_requests": blocked,
        "companies": ordered,
    }


def _devices_by_id(conn) -> dict[int, dict]:
    return {row["id"]: dict(row) for row in conn.execute("SELECT * FROM devices").fetchall()}


def build_privacy_report(conn, hours: int = 24) -> dict:
    hours = _clamp_hours(hours)
    by_device: dict[int | None, list[dict]] = defaultdict(list)
    for row in _domain_counts(conn, hours):
        by_device[row["device_id"]].append(row)
    devices = _devices_by_id(conn)

    device_reports = []
    company_totals: dict[str, dict] = {}
    totals = {"dns_queries": 0, "tracker_requests": 0, "blocked_requests": 0}
    for device_id, rows in by_device.items():
        summary = _summarize(rows)
        for key in totals:
            totals[key] += summary[key]
        if not summary["tracker_requests"]:
            continue
        device = devices.get(device_id) if device_id is not None else None
        device_reports.append(
            {
                "device_id": device_id,
                "name": device_display_name(device),
                "vendor": device.get("vendor") if device else None,
                "device_type": device.get("device_type") if device else None,
                **summary,
            }
        )
        for company in summary["companies"]:
            total = company_totals.setdefault(
                company["company"],
                {
                    "company": company["company"],
                    "category": company["category"],
                    "requests": 0,
                    "blocked": 0,
                    "devices": 0,
                },
            )
            total["requests"] += company["requests"]
            total["blocked"] += company["blocked"]
            total["devices"] += 1

    device_reports.sort(key=lambda item: (-item["tracker_requests"], item["name"]))
    top_companies = sorted(company_totals.values(), key=lambda item: (-item["requests"], item["company"]))
    return {
        "hours": hours,
        "devices": device_reports,
        "top_companies": top_companies[:15],
        "totals": {
            **totals,
            "companies": len(company_totals),
            "devices_tracked": len(device_reports),
        },
    }


def build_device_privacy(conn, device: dict, hours: int = 24) -> dict:
    hours = _clamp_hours(hours)
    summary = _summarize(_domain_counts(conn, hours, device_id=device["id"]))
    return {
        "device_id": device["id"],
        "name": device_display_name(device),
        "hours": hours,
        **summary,
    }
