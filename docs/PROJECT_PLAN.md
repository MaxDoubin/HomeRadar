# Home Radar - Project Plan
## Congressional App Challenge 2026 | NV-03 (Susie Lee) | Max Doubin

---

## The Pitch

Every American family has an old laptop collecting dust. Meanwhile, home networks are
completely invisible - families have no idea what devices are connected, what data is
leaving their house, or whether they're exposed to threats. Home Radar turns that
forgotten device into a free, enterprise-inspired home-network security appliance. Download,
flash, plug in, protected.

**Cost to the family: $0.**

---

## What Home Radar Does

### Core Features (MVP - Must Ship)

1. **One-Click Install** - Bootable USB ISO (Debian-minimal based) that turns any old
   laptop/desktop into a dedicated appliance. Also ships as a Docker one-liner for users
   who want to run it alongside an existing OS.
2. **Network Discovery & Device Inventory** - ARP scanning + mDNS/SSDP/UPnP passive
   listening to auto-discover every device on the network. Fingerprints devices by MAC
   OUI, hostname, open ports, and traffic behavior. Categorizes them (phone, smart TV,
   IoT camera, laptop, unknown).
3. **Live Dashboard** - Clean, responsive React web UI accessible from any phone or
   laptop on the local network. Shows all devices, a household "security score" (0–100),
   active alerts, and traffic stats. The old laptop's own screen shows a persistent status
   display (green/yellow/red, device count, alert ticker).
4. **New Device Alerts** - Instant browser push notification and dashboard alert when an
   unknown device joins the network. "A new device just connected: Unknown - MAC
   xx:xx:xx:xx:xx:xx. Authorize or block?"
5. **DNS-Level Threat Blocking** - Built-in DNS proxy that blocks known malware domains,
   phishing sites, and ad trackers using community blocklists (Steven Black's hosts,
   OISD, etc.) plus threat intel feeds. Families get Pi-hole-level blocking with zero
   setup.
6. **Outbound Traffic Monitor** - Flags devices making connections to known-bad
   IPs/domains (checked against AbuseIPDB, CISA Known Exploited Vulnerabilities catalog,
   and community threat intel). Alerts like: "Your smart TV contacted 3 suspicious IPs in
   the last hour."
7. **Device Trust Scoring** - Each device earns a trust score over time based on
   behavior: how much data it sends, where it connects, how often it phones home, whether
   it communicates with other LAN devices unexpectedly. Anomalies drop the score and
   trigger alerts.
8. **Weekly Security Digest** - Automated email summary to the household: new devices
   this week, blocked threats, trust score changes, and one actionable security tip.

### Stretch Features (Post-MVP / 2.0 Story for Application)

- [x] ML anomaly detection (Isolation Forest or Autoencoder) on traffic patterns to catch
  zero-day-style behavior without signature matching
- [x] Per-device DNS internet pause, quiet-hour schedules, and custom domain rules
- [x] Bandwidth usage monitoring per device
- [x] Non-invasive service exposure audit from observed ports (no credential attempts)
- [x] Integration with Flipper Zero for live attack demo (deauth detection, rogue AP
  detection)
- [x] Mobile companion apps (native iOS/SwiftUI and Android/Kotlin) for push notifications
- [x] Auto-update mechanism for blocklists and threat intel

---

## Technical Architecture

```
                    INTERNET
                       |
                   [ ROUTER ]
                       |
              [ OLD LAPTOP / PC ]
              Running Home Radar OS
                       |
          +-----------+-----------+
          |           |           |
       [Phone]    [Laptop]    [IoT TV]
          |           |           |
       (all traffic passes through
        Home Radar's DNS proxy;
        ARP/passive monitoring
        sees all LAN traffic)
```

### Stack

| Layer | Technology |
|---|---|
| **OS Base** | Debian 12 Minimal (custom ISO via live-build) |
| **Backend API** | Python 3.11+ / FastAPI |
| **Network Discovery** | scapy (ARP), python-nmap, zeroconf (mDNS) |
| **DNS Proxy** | dnsmasq or custom Python DNS server (dnspython) |
| **Packet Analysis** | scapy + pyshark for deep inspection |
| **Threat Intel** | AbuseIPDB API, CISA KEV JSON feed, community blocklists |
| **Database** | SQLite (local, zero-config, portable) |
| **Dashboard Frontend** | React 19 + custom responsive CSS + hand-built SVG charts |
| **Status Display** | Chromium kiosk mode on the appliance's own screen |
| **Email Digest** | Python smtplib, Jinja2 templates |
| **Process Management** | systemd services |
| **Build System** | live-build (ISO), Docker Compose (container option) |

### Network Positioning

Home Radar operates in **passive monitoring + DNS proxy** mode. It does not need to be
inline (no bridging, no breaking the network). It:

1. Runs on the LAN alongside all other devices
2. Uses ARP scanning and passive sniffing (promiscuous mode) to observe traffic
3. Acts as the network's DNS server (router's DHCP points clients to Home Radar's IP for
   DNS)
4. This gives it visibility into every device's DNS queries (what domains they contact)
   plus Layer 2/3 traffic metadata

If Home Radar is the only DNS resolver distributed by the router and it goes down, name
resolution can stop until the router configuration is rolled back. The original DNS
settings must therefore be documented and a tested recovery plan kept available.

---

## Development Timeline

### Phase 1: Foundation - 2 weeks

- [x] Initialize GitHub repo with README, LICENSE (MIT), CONTRIBUTING.md
- [x] Set up Python project structure with FastAPI skeleton
- [x] Build ARP scanner module (scapy) - discover all LAN devices
- [x] Build MAC OUI lookup for device manufacturer identification
- [x] Build multi-signal device fingerprinting (OUI + hostname + ports + mDNS + SSDP)
- [x] Add mDNS/DNS-SD, SSDP/UPnP, and neighbor-cache discovery
- [x] Set up SQLite database schema (devices, events, alerts, traffic_logs, trust_scores)
- [x] Build basic REST API: GET /devices, GET /alerts, GET /status
- [x] Add inventory summary API and fingerprint evidence/confidence
- [ ] Test on your home network - verify it finds all your devices

**Milestone: Plug in a machine, run a script, see every device on your network in the
terminal.**

### Phase 2: DNS Proxy & Threat Blocking - 2 weeks

- [x] Build DNS proxy server (intercept DNS queries, resolve or block)
- [x] Integrate community blocklists (auto-download and parse Steven Black, OISD)
- [x] Build blocklist update systemd timer
- [x] Log all DNS queries per device (store in SQLite)
- [x] Integrate cached AbuseIPDB API reputation lookups
- [x] Integrate CISA KEV feed as a software-vulnerability catalog
- [x] Build optional outbound connection monitor (flag connections to bad IPs)
- [x] New device detection + deduplicated alert generation

**Milestone: DNS blocking is live, malware domains are blocked, bad outbound connections
are flagged.**

### Phase 3: Dashboard - 3 weeks

- [x] React project setup with responsive custom CSS
- [x] Dashboard home page: security score, device count, active alerts, 24h traffic
      sparkline
- [x] Devices page: grid/list of all devices with type icon, name, IP, MAC, trust score,
      last seen
- [x] Device detail view: DNS query history, traffic stats, trust score breakdown,
      authorize/block
- [x] Alerts page: chronological feed with severity, device, description
- [x] Traffic page: traffic metadata, top domains, blocked queries chart
- [x] Settings page: email config, DNS settings, alert preferences
- [x] WebSocket for real-time updates and browser notifications
- [x] Interactive household network map visualization
- [x] Build kiosk status display for the appliance's own screen

**Milestone: Full working dashboard accessible from any phone on the network.**

### Phase 4: Trust Scoring & Intelligence - 2 weeks

- [x] Design explainable trust scoring algorithm:
  - Base score: 50 (new device)
  - +points: recognized manufacturer, expected behavior, low outbound variance
  - -points: contacts known-bad IPs, unusual DNS queries, high data volume, unexpected
    LAN scanning
- [x] Historical behavior tracking per device
- [x] Anomaly flagging using online per-device statistical baselines
- [x] Weekly email digest builder and SMTP delivery
- [x] Security score calculation for the whole household (weighted average of all device
      trust scores + blocked threats + open issues)

**Milestone: Every device has a live trust score, household gets a weekly security
email.**

### Phase 5: Packaging & Polish - 2 weeks

- [x] Add Debian live ISO build configuration (physical boot validation remains)
- [x] Build Docker Compose alternative install
- [x] Write install guide (Docker, native Debian, DNS activation, rollback, ISO)
- [x] First-run setup wizard in the dashboard (set household name, email for digest,
      confirm DNS)
- [ ] 3D print a small case badge or stand for the "Home Radar appliance" look (optional
      but nice)
- [ ] Test on multiple old machines (different specs, architectures)
- [ ] Test on your home network for a full week in production mode
- [x] Write full README with architecture and install steps
- [ ] Add final screenshots captured from validated hardware

**Milestone: Anyone can download the ISO, flash it, and be running in under 10 minutes.**

### Phase 6: Demo & Submission - 2 weeks

- [ ] Record demo video (under 2 minutes):
  - Show the old laptop, explain it was collecting dust
  - Flash the USB, boot Home Radar
  - Plug in ethernet
  - Open dashboard on phone - devices appear
  - Show a blocked threat in real time
  - Show the Flipper Zero attempting an attack, Home Radar catching it
  - Show the security score, the network map, the weekly digest
  - End with the pitch: "$0. Open source. Every family."
- [ ] Take cover photo (dashboard on phone with the appliance in background, 600x800
      JPEG 3:4)
- [ ] Fill out all application fields
- [ ] Push final code to GitHub (clean commits, good README, MIT license)
- [ ] Opt in for Hack Club Congressional Certification (open source requirement met)
- [ ] Submit before October 26

---

## Application Answers (Draft Outlines)

**What is your app called?**
Home Radar

**Programming languages:**
Python, JavaScript, Swift, Kotlin

**Platform:**
Web, iOS, Android

**What does your app do? (400 words)**
Core angles: turns e-waste into security appliance, $0 cost, network discovery, DNS
threat blocking, device trust scoring, real-time dashboard, weekly digest, open source.

**What inspired you? (400 words)**
Core angles: You have a petabyte homelab with enterprise gear - your neighbors have
nothing. You did a formal network security risk assessment of your school (South CTA
PBL). You're a Henderson Blue Ribbon Commissioner and see digital equity gaps firsthand.
You teach at youth coding camps and know most families have zero network visibility.
50M tons of e-waste per year. You wanted to fix both problems at once.

**Technical difficulties? (400 words)**
Core angles: Passive monitoring without being inline, DNS proxy reliability, device
fingerprinting accuracy, building a full Linux ISO from scratch, making it work on
wildly different old hardware, balancing security depth with a UI your grandparents can
understand.

**2.0 improvements? (400 words)**
Core angles: ML anomaly detection, mobile app, Flipper Zero integration for attack
detection, parental controls, automatic vulnerability scanning, mesh support for larger
homes, community threat sharing between Home Radar nodes.

**Did you use AI?**
Yes - used Claude for architecture planning, code review, debugging, and documentation.
All core logic (network scanning, DNS proxy, trust scoring algorithm, dashboard design)
was designed and implemented by me. AI was a development tool, not the developer.

**What did you learn? (400 words)**
Core angles: Linux system engineering, network protocol internals, threat intelligence
pipelines, full-stack development, open-source community building, turning a real-world
problem you care about into software anyone can use.

---

## Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Old hardware compatibility | Test on 3+ machines of different ages; Debian supports nearly everything |
| DNS proxy breaks family internet | Failsafe: if Home Radar DNS goes down, devices fall back to router DNS via DHCP timeout |
| Judges can't test it live | Demo video shows full plug-in-and-go flow; GitHub README has Docker one-liner for instant test |
| Scope creep | MVP features are locked above; ML and mobile app are explicitly "2.0" stretch goals |
| Threat intel API rate limits | Cache AbuseIPDB lookups in SQLite; CISA KEV is a static JSON file (no rate limit) |

---

## Resources Needed

- [x] GitHub repo (free)
- [ ] AbuseIPDB API key (free tier: 1,000 lookups/day - plenty for a home network)
- [ ] One old laptop/desktop for primary testing (you have plenty of gear)
- [ ] Your homelab for development
- [ ] USB flash drive for ISO testing
- [ ] Flipper Zero for attack demo (you have this)
- [ ] Optional: Raspberry Pi for secondary deployment target
- [ ] Phone for recording demo video

---

## Competition Differentiators

1. **$0 cost** - No other security product does this. Firewalla is $200+. Pi-hole
   requires a Pi. Home Radar requires nothing you don't already own.
2. **E-waste repurposing** - Environmental angle that resonates with congressional
   offices.
3. **Truly open source (MIT)** - Qualifies for Hack Club Congressional Certification.
4. **Real hardware + software** - Not just a web app. Physical appliance built from
   recycled hardware.
5. **Enterprise concepts made accessible** - Network monitoring, threat intel, trust
   scoring - concepts from your CTE program, made family-friendly.
6. **Proven personal story** - You already presented a network security assessment to
   school administration. This is the logical next step.
7. **Live demo potential** - At #HouseOfCode, plug it into the venue's network and map it
   in real time in front of Congress.

---

*Last updated: July 27, 2026*
*Congressional App Challenge Deadline: October 26, 2026*
