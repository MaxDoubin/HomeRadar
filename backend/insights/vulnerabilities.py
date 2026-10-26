"""Match device makers against CISA's Known Exploited Vulnerabilities catalog.

The catalog (stored locally in ``cisa_kev`` by backend.monitor.cisa_kev) lists
vulnerabilities attackers are actively exploiting, keyed by vendor and
product. Home Radar usually knows only a device's *manufacturer* (from its MAC
address), not its exact model or firmware, so every result here is phrased as
"products from this maker", never "this device is vulnerable".

Matching is intentionally strict: a device vendor string only matches when it
normalizes to one of the curated brands below, and the catalog side matches the
same brand by exact normalized vendor name. Network-chip makers (Espressif,
Realtek, Qualcomm, ...) are never matched, because the MAC address of a smart
plug or laptop often names the Wi-Fi chip's maker rather than the product's.
"""
from __future__ import annotations

import re

from backend.db import models
from backend.insights import device_display_name
from backend.insights.kev_sample import KEV_SAMPLE

# brand key -> (display name, device-vendor prefixes, catalog vendor names)
BRANDS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "tplink": ("TP-Link", ("tplink",), ("TP-Link",)),
    "netgear": ("NETGEAR", ("netgear",), ("NETGEAR",)),
    "dlink": ("D-Link", ("dlink",), ("D-Link",)),
    "asus": ("ASUS", ("asus",), ("ASUS",)),
    "zyxel": ("Zyxel", ("zyxel",), ("Zyxel",)),
    "linksys": ("Linksys", ("linksys", "ciscolinksys", "belkinlinksys"), ("Linksys",)),
    "cisco": ("Cisco", ("cisco",), ("Cisco",)),
    "ubiquiti": ("Ubiquiti", ("ubiquiti",), ("Ubiquiti",)),
    "mikrotik": ("MikroTik", ("mikrotik", "routerboard"), ("MikroTik",)),
    "draytek": ("DrayTek", ("draytek",), ("DrayTek",)),
    "tenda": ("Tenda", ("tenda",), ("Tenda",)),
    "synology": ("Synology", ("synology",), ("Synology",)),
    "qnap": ("QNAP", ("qnap",), ("QNAP",)),
    "hikvision": ("Hikvision", ("hikvision",), ("Hikvision",)),
    "dahua": ("Dahua", ("dahua",), ("Dahua",)),
    "reolink": ("Reolink", ("reolink",), ("Reolink",)),
    "geovision": ("GeoVision", ("geovision",), ("GeoVision",)),
    "samsung": ("Samsung", ("samsung",), ("Samsung",)),
    "apple": ("Apple", ("apple",), ("Apple",)),
    "google": ("Google", ("google",), ("Google",)),
    "microsoft": ("Microsoft", ("microsoft",), ("Microsoft",)),
    "fortinet": ("Fortinet", ("fortinet",), ("Fortinet",)),
    "dell": ("Dell", ("dell",), ("Dell",)),
    "gigabyte": ("GIGABYTE", ("gigabyte",), ("GIGABYTE",)),
    "lenovo": ("Lenovo", ("lenovo",), ("Lenovo",)),
    "lg": ("LG", ("lgelectronics",), ("LG",)),
    "sony": ("Sony", ("sony",), ("Sony",)),
    "roku": ("Roku", ("roku",), ("Roku",)),
    "amazon": ("Amazon", ("amazon",), ("Amazon",)),
    "xiaomi": ("Xiaomi", ("xiaomi",), ("Xiaomi",)),
    "huawei": ("Huawei", ("huawei",), ("Huawei",)),
    "belkin": ("Belkin", ("belkin",), ("Belkin",)),
}

CHIP_MAKERS = (
    "espressif", "realtek", "mediatek", "qualcomm", "broadcom", "intel", "murata",
    "azurewave", "honhai", "foxconn", "liteon", "texasinstruments", "siliconlabs",
    "marvell", "nordicsemiconductor", "cypress", "infineon", "nxp", "ampak",
    "universalglobalscientific", "armlimited",
)

_LOCATION_WORDS = frozenset({
    "hangzhou", "zhejiang", "shenzhen", "guangdong", "guangzhou", "beijing",
    "shanghai", "fujian", "xiamen", "dongguan", "suzhou", "nanjing",
})

_PREFIX_TO_BRAND = sorted(
    ((prefix, key) for key, (_, prefixes, _) in BRANDS.items() for prefix in prefixes),
    key=lambda item: -len(item[0]),
)


def normalize_vendor(value: str | None) -> str:
    """Lowercase, drop punctuation and leading city/province names, join tokens."""
    tokens = re.findall(r"[a-z0-9]+", (value or "").lower())
    while tokens and tokens[0] in _LOCATION_WORDS:
        tokens.pop(0)
    return "".join(tokens)


def is_chip_maker(vendor: str | None) -> bool:
    compact = normalize_vendor(vendor)
    return bool(compact) and (compact == "arm" or compact.startswith(CHIP_MAKERS))


def brand_for_vendor(vendor: str | None) -> str | None:
    """Return the curated brand key for a device vendor string, or None."""
    compact = normalize_vendor(vendor)
    if not compact or is_chip_maker(vendor):
        return None
    for prefix, key in _PREFIX_TO_BRAND:
        if compact.startswith(prefix):
            return key
    return None


_CATALOG_VENDOR_TO_BRAND = {
    normalize_vendor(name): key for key, (_, _, names) in BRANDS.items() for name in names
}


def brand_for_catalog_vendor(vendor_project: str | None) -> str | None:
    return _CATALOG_VENDOR_TO_BRAND.get(normalize_vendor(vendor_project))


def catalog_meta(conn) -> dict:
    row = conn.execute("SELECT COUNT(*) AS size, MAX(updated_at) AS updated FROM cisa_kev").fetchone()
    size = int(row["size"] or 0)
    is_sample = (
        size > 0
        and size <= len(KEV_SAMPLE)
        and models.get_setting(conn, "cisa_kev_demo_sample") == "true"
    )
    return {"catalog_size": size, "catalog_updated_at": row["updated"], "catalog_is_sample": is_sample}


def _catalog_by_brand(conn) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    rows = conn.execute(
        """SELECT cve_id, vendor_project, product, vulnerability_name, date_added, ransomware_use
           FROM cisa_kev"""
    ).fetchall()
    for row in rows:
        brand = brand_for_catalog_vendor(row["vendor_project"])
        if brand:
            grouped.setdefault(brand, []).append(dict(row))
    for entries in grouped.values():
        entries.sort(key=lambda item: (item["date_added"] or "", item["cve_id"]), reverse=True)
    return grouped


def _device_entry(device: dict, catalog: dict[str, list[dict]], is_sample: bool = False) -> dict:
    vendor = device.get("vendor")
    brand_key = brand_for_vendor(vendor)
    entries = catalog.get(brand_key, []) if brand_key else []
    brand = BRANDS[brand_key][0] if brand_key else None
    if not vendor:
        status, advice = "no_vendor", "Home Radar doesn't know who made this device yet."
    elif is_chip_maker(vendor):
        status = "chip_maker"
        advice = (
            f"{vendor} makes network chips used inside many brands' products, so it doesn't "
            "identify this device's brand. Home Radar doesn't match it against the catalog."
        )
    elif not brand_key:
        status, advice = "unknown_brand", "Home Radar couldn't match this maker to the CISA catalog."
    elif entries:
        status = "catalog_matches"
        noun = "vulnerability" if len(entries) == 1 else "vulnerabilities"
        source = "A sample of CISA's catalog lists" if is_sample else "CISA lists"
        advice = (
            f"{source} {len(entries)} actively exploited {noun} in products from {brand}. "
            "That doesn't mean this device is affected, but make sure its software is up to date."
        )
    elif is_sample:
        status = "not_in_sample"
        advice = (
            f"The demo sample of CISA's catalog doesn't cover {brand}. "
            "Download the full catalog from Settings for a real check."
        )
    else:
        status = "no_known"
        advice = f"CISA lists no actively exploited vulnerabilities in products from {brand}."
    return {
        "device_id": device["id"],
        "name": device_display_name(device),
        "vendor": vendor,
        "brand": brand,
        "status": status,
        "kev_count": len(entries),
        "recent": [
            {
                "cve_id": item["cve_id"],
                "product": item["product"],
                "vulnerability_name": item["vulnerability_name"],
                "date_added": item["date_added"],
                "known_ransomware_use": (item["ransomware_use"] or "").lower() == "known",
            }
            for item in entries[:5]
        ],
        "advice": advice,
    }


_EMPTY_MESSAGE = (
    "The CISA catalog hasn't been downloaded yet. Update it from Settings to check your devices."
)


def check_household(conn) -> dict:
    meta = catalog_meta(conn)
    if not meta["catalog_size"]:
        return {"status": "catalog_empty", "message": _EMPTY_MESSAGE, **meta, "devices": []}
    catalog = _catalog_by_brand(conn)
    devices = [
        _device_entry(device, catalog, meta["catalog_is_sample"]) for device in models.list_devices(conn)
    ]
    devices.sort(key=lambda item: (-item["kev_count"], item["name"]))
    return {
        "status": "ok",
        **meta,
        "devices_with_matches": sum(1 for item in devices if item["kev_count"]),
        "devices": devices,
    }


def check_device(conn, device: dict) -> dict:
    meta = catalog_meta(conn)
    if not meta["catalog_size"]:
        return {"status": "catalog_empty", "message": _EMPTY_MESSAGE, **meta, "device": None}
    entry = _device_entry(device, _catalog_by_brand(conn), meta["catalog_is_sample"])
    return {"status": "ok", **meta, "device": entry}
