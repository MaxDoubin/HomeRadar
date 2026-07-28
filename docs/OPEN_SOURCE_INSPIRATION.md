# Open-source inspiration and attribution

Home Radar's implementation is original MIT-licensed code. No source code was copied
from the projects below. They were studied as prior art for product behavior and
operational design.

## AdGuard Home

- Project: [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
- License: [GPL-3.0](https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt)
- Ideas studied: multiple upstream resolvers, fallback behavior, per-client policy,
  cache controls, and suppression of simultaneous duplicate upstream requests.
- Home Radar adaptation: resolver IPs are tried in observed-health order; failures
  automatically fall through. Identical cache-miss queries share one in-flight lookup.

## Technitium DNS Server

- Project: [Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer)
- License: [GPL-3.0](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE)
- Ideas studied: local DNS caching, latency-aware resolver selection, blocklist
  normalization, and transparent operational statistics.
- Home Radar adaptation: a bounded in-memory LRU cache honors the smallest answer TTL,
  lowers returned TTLs as entries age, rewrites transaction IDs per client, and never
  caches empty or error responses.

## Pi-hole FTL

- Project: [Pi-hole FTL](https://github.com/pi-hole/FTL)
- License: [upstream license](https://github.com/pi-hole/FTL/blob/master/LICENSE)
- Ideas studied: making lightweight DNS statistics available through an appliance API.
- Home Radar adaptation: `/dns/stats` exposes cache entries, hits, misses, hit rate,
  per-upstream request count, failures, and smoothed latency. `/dns/cache/clear` provides
  an explicit operational reset.

## License boundary

Studying a feature does not import another project's implementation or license into Home
Radar. These citations are included for transparency and respect for the open-source
projects that established the product patterns.
