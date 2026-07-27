# Security pipeline

## DNS firewall

`backend/dns/proxy.py` is a concurrent UDP and TCP DNS proxy. It retries truncated UDP
answers over TCP. For each request it:

1. parses the DNS question;
2. attributes the source IP to an inventoried device;
3. refuses requests from devices the household marked blocked;
4. checks the exact domain and each parent domain against the in-memory blocklist;
5. returns `NXDOMAIN` for a blocklist match or forwards the original packet upstream;
6. records domain, type, byte counts, result, device, and reason in SQLite.

Remote blocklists are normalized into a deterministic local file and replaced atomically.
StevenBlack and OISD endpoints are defaults, can be replaced by environment configuration,
and update through a systemd timer or the API. The proxy keeps serving the previous list
if a download fails.

## Threat intelligence

Public destination IPs can be checked against AbuseIPDB when an API key is configured.
Results are cached with an expiry to protect the free-tier rate limit. Private,
link-local, multicast, loopback, and reserved addresses never leave the appliance.

The CISA Known Exploited Vulnerabilities catalog is stored separately and searchable.
CISA KEV is a software-vulnerability catalog, not a bad-IP feed; Home Radar does not
mislabel it as network reputation. It is ready for version-aware device correlation as
fingerprinting gains firmware details.

## Traffic observation

DNS logging is the reliable household visibility path. An optional Scapy observer also
aggregates public IPv4 flows by source/destination before reputation analysis. On switched
networks it can only observe traffic visible to the appliance interface unless switch
port mirroring is enabled.

## Explainable trust

Every device starts at 50. Recognition, strong fingerprint confidence, and explicit
household authorization add points. Blocking, known-bad activity, repeated blocked DNS,
high domain variance, and unresolved alerts subtract points. Scores are clamped to
0-100; changes and reasons are stored in `trust_scores`.

An online mean/variance baseline tracks hourly query count, unique domains, and observed
bytes. After enough samples, activity at least three standard deviations above the
device's own baseline creates a deduplicated anomaly alert. This intentionally uses
small-data statistics instead of a black-box model so a family can understand the alert.

The household score is the average device trust score minus a severity-weighted open
alert penalty. Dashboard and weekly-digest values come from the same calculation.

## Operational resilience

An hourly maintenance worker prunes expired threat cache, old traffic metadata, and old
resolved alerts. It uses SQLite's online backup API to create a daily copy, runs
`PRAGMA quick_check` against the copy, and only then exposes it for download. Backup
filenames are validated before file access.

The health endpoint checks the live database, data-volume free space, DNS settings,
blocklist presence/freshness, latest discovery timestamp, and backup count. The dashboard
surfaces degraded conditions without exposing credentials.
