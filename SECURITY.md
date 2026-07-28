# Home Radar Security Policy

## Supported versions

Home Radar is still under active development. Security fixes are applied to the latest `main` branch and the newest release generated from it.

| Version | Security updates |
|---|---|
| Latest release / `main` | Yes |
| Older development snapshots | No |

## Report a vulnerability privately

Please do not publish exploit details in a normal issue, discussion, pull request, or social-media post.

1. Open the repository's **Security** tab.
2. Choose **Advisories** and then **Report a vulnerability** or **New draft security advisory**.
3. Include the affected version or commit, impact, reproduction steps, logs, and a suggested fix when available.
4. Remove household IP addresses, MAC addresses, DNS history, tokens, API keys, and other personal network data from screenshots or logs.

If GitHub private vulnerability reporting is unavailable, create a minimal public issue stating only that you need a private security contact. Do not include the vulnerability details in that issue.

## Deployment boundary

Home Radar is intended for a trusted home LAN or a properly secured private VPN. It is not designed to be exposed directly to the public internet.

- Keep TCP port 8000 behind the home router or private VPN.
- Do not forward the dashboard port from the public internet.
- Generate pairing codes only when adding a device.
- Rotate the management token if a paired device is lost, sold, or compromised.
- Keep the operating system, Docker Engine, and Home Radar image updated.
- Verify release downloads with `SHA256SUMS.txt`.
- Use a unique SMTP application password when email digests are enabled.
- Treat exported SQLite backups as sensitive household data.

## Authentication model

- The appliance's own loopback browser can bootstrap the initial management token.
- Remote browsers and mobile applications exchange a six-digit, ten-minute, single-use code for the management token.
- Repeated incorrect code attempts trigger a temporary lockout.
- Sensitive inventory, traffic, alert, settings, backup, digest, DNS, and threat-intelligence endpoints require authentication for remote clients.
- Modifying endpoints also enforce token checks at the route level.
- Remote WebSocket sessions require the same token.
- Cross-origin browser access is disabled unless trusted origins are explicitly configured.

## Data handled by Home Radar

Home Radar may store device names, MAC addresses, local IP addresses, DNS query metadata, alerts, trust history, settings, and backups in local SQLite files. This information can reveal household behavior and must be protected accordingly.

Home Radar does not upload this database to a Home Radar cloud service. Optional third-party integrations may transmit limited data:

- AbuseIPDB receives public destination IP addresses when enabled.
- The configured SMTP provider receives security digest email content.
- Community blocklists and the CISA catalog are downloaded from their publishers.

## Security limitations

Home Radar is a visibility and DNS-policy appliance, not a replacement for router firmware, endpoint protection, or a professionally managed firewall.

- DNS controls do not stop direct-IP connections or encrypted DNS that bypasses the configured resolver.
- Passive observation may be incomplete on switched or isolated networks.
- Device classification is evidence-based and may remain unknown.
- Service-exposure checks use a limited set of common ports and do not attempt passwords or exploits.
- Experimental anomaly detection can produce false positives and must remain explainable to the user.
