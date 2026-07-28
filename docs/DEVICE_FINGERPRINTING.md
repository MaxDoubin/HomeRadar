# Device Fingerprinting

Home Radar identifies devices by combining weak signals instead of treating any single
signal as truth. This matters because vendors build many product types, hostnames can be
renamed, ports are reused, and modern phones often randomize their MAC addresses.

## Discovery signals

| Signal | Examples | Strength |
|---|---|---|
| ARP + neighbor cache | IPv4 address, stable LAN MAC | Identity and presence |
| IEEE OUI | Synology, Ubiquiti, Brother, Raspberry Pi | Brand; sometimes category |
| Reverse DNS | `office-printer`, `living-room-roku` | User/device-provided hint |
| Targeted TCP services | RTSP, IPP, Roku control, Home Assistant, Plex | Strong category evidence |
| mDNS/DNS-SD | AirPlay, Cast, Sonos, HomeKit, Matter, printers | Strong advertised capability |
| SSDP/UPnP | Internet gateway, media renderer, console | Strong advertised device role |
| Model/service names | Chromecast, Hue Bridge, HomePod | Strong product-family evidence |

## Confidence and evidence

Each matching signal adds weighted points to one or more categories. Strongly
device-specific signals-such as IPP printing, Roku control, Home Assistant, or an
InternetGatewayDevice advertisement-carry more weight than generic services such as SSH
or a web interface.

The API returns:

- `device_type`: the highest-scoring category;
- `fingerprint_confidence`: confidence from `0.0` to `0.99`;
- `model`: the best advertised model string;
- `services`: mDNS and SSDP service identifiers;
- `discovery_sources`: how the device was found;
- `fingerprint.evidence`: human-readable reasons for the result;
- `fingerprint.scores`: competing category scores.

When evidence is insufficient, the classifier returns `unknown` with zero confidence.
That is safer than confidently assigning the wrong icon or security policy.

## Privacy and safety

Discovery stays on the local network. The scanner uses a small, curated port set intended
for identity-not a broad vulnerability scan-and does not fetch arbitrary UPnP
description URLs. MAC vendor lookup is local and randomized/private MACs are labeled as
such instead of being falsely attributed to a manufacturer.
