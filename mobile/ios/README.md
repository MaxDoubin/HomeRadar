# HomeRadar iOS Companion App

Source for a native SwiftUI companion app to the HomeRadar appliance, at
`mobile/ios/HomeRadar/`. This is source code only -- **there is no
`.xcodeproj` in this directory**, and nothing here has been opened,
resolved, compiled, or run. It was written in a Linux sandbox with no
Swift toolchain or Xcode available at all (not even enough to run
`swift -frontend -parse` on a single file), by careful reading of the
Swift/SwiftUI/Foundation/Network/Security API surface. An engineer must
turn it into a real Xcode project and build it on a Mac before any of it
can be considered working.

## Layout

```
mobile/ios/
  README.md              <- this file
  HomeRadar/
    project.yml           <- xcodegen spec (see Option A below)
    HomeRadar/             <- app sources
    HomeRadarTests/         <- unit test sources
```

## Turning this into a buildable Xcode project

You cannot hand-author a real `.xcodeproj` (it's a binary-adjacent plist
bundle with generated UUIDs) reliably outside Xcode, so pick one of:

### Option A (recommended): xcodegen

[XcodeGen](https://github.com/yonaskolb/XcodeGen) generates a `.xcodeproj`
from the plain-text `project.yml` already included in this directory.

```sh
brew install xcodegen
cd mobile/ios/HomeRadar
xcodegen generate
open HomeRadar.xcodeproj
```

This creates `HomeRadar.xcodeproj` with two targets (`HomeRadar` app,
`HomeRadarTests` unit tests) wired to the `HomeRadar/` and
`HomeRadarTests/` source directories, an iOS 16.0 deployment target, and
the Info.plist entries described below. Re-run `xcodegen generate` any
time files are added or removed.

### Option B: manual Xcode project

1. In Xcode: **File > New > Project... > iOS > App**. Name it `HomeRadar`,
   interface **SwiftUI**, language **Swift**. Uncheck "Include Tests" (add
   the test target separately below) or leave it checked and delete its
   placeholder file.
2. Delete the template's placeholder `ContentView.swift` and default
   `HomeRadarApp.swift` (or just overwrite them).
3. Drag every file under `mobile/ios/HomeRadar/HomeRadar/` into the
   project navigator, preserving the folder structure shown above
   (Overview/, Devices/, Alerts/, Settings/, Connect/, Networking/,
   Notifications/) as groups, with "Copy items if needed" **unchecked**
   (reference in place) and "Create groups" selected, added to the
   `HomeRadar` target.
4. Add a unit test target: **File > New > Target... > iOS > Unit Testing
   Bundle**, name it `HomeRadarTests`, host application `HomeRadar`. Drag
   in every file under `mobile/ios/HomeRadar/HomeRadarTests/`, added to
   the `HomeRadarTests` target.
5. Set the deployment target to iOS 16.0 or later on the `HomeRadar`
   target (the app uses `NavigationStack`, which requires iOS 16+).
6. Add the Info.plist entries listed below to the generated Info.plist (or
   the target's Info tab, depending on your Xcode version's default
   Info.plist handling).

## Required Info.plist entries

Whichever option you use, the app needs these (already wired into
`project.yml` for Option A):

| Key | Value | Why |
|---|---|---|
| `NSLocalNetworkUsageDescription` | a user-facing string, e.g. "HomeRadar scans your local network for your HomeRadar security appliance so you can pair with it." | `ApplianceDiscovery.swift`'s `NWBrowser` Bonjour scan triggers iOS's Local Network privacy prompt; without this key the OS silently returns no results. |
| `NSBonjourServices` | array containing `_http._tcp` | Same reason -- iOS 14+ requires declaring which Bonjour service types the app is allowed to browse. |
| `NSAppTransportSecurity` > `NSAllowsLocalNetworking` | `true` | The appliance is plain `http://` with no TLS (by design, per the backend contract). This ATS carve-out allows non-secure loads to IP-literal, `.local`, and no-dot LAN hostnames without the much broader `NSAllowsArbitraryLoads` exception. It's a heuristic, not a guarantee -- if a household ever enters an address ATS doesn't recognize as "local," this may need revisiting (e.g. an `NSExceptionDomains` entry for a specific hostname pattern, or a wider exception, at the integrating engineer's discretion). |

## Design notes for the engineer picking this up

- **Everything funnels through one client.** `HomeRadarClient.attachAuth(_:)`
  is the single place the `X-HomeRadar-Token` header gets set. No call
  site sets it ad hoc.
- **`Alert.isResolved` is `Int`, `AlertResolveResult.isResolved` is `Bool`.**
  This is not a mistake -- see the doc comments on both types in
  `Networking/APIModels.swift`. Every alert response *except* the `PATCH
  /alerts/{id}` response serializes straight from a SQLite row with no
  Pydantic model in between, so `is_resolved` arrives as a raw `0`/`1`.
  Do not merge these two types.
- **Timestamps need `.withFractionalSeconds`.** A bare
  `ISO8601DateFormatter()` cannot parse
  `"2026-07-28T12:34:56.789012+00:00"`. See `HomeRadarDateParsing` in
  `Networking/APIModels.swift`. Any UI that shows a device/alert timestamp
  falls back to a "last seen unknown"-style string rather than
  force-unwrapping a failed parse.
- **The websocket reconnect backoff (2.5s -> 5s -> 10s -> capped 15s,
  reset on success) is intentionally more aggressive than the web
  dashboard's flat retry.** Mobile networks drop connections far more
  often than a wired appliance-to-browser session. See the doc comment on
  `nextBackoffInterval(previous:)` in `Networking/DashboardSocket.swift`.
- **True background push (APNs) is out of scope this pass.** See the
  `TODO(v2, ...)` comment at the top of
  `Notifications/LocalAlertNotifier.swift`. Only local notifications fired
  while the app process is alive and the websocket is connected are
  implemented. The notification permission prompt is tied to the Settings
  screen's toggle (`SettingsViewModel.requestNotificationAuthorizationIfNeeded()`),
  never fired unconditionally at launch.
- **Explicitly out of scope this pass** (per the product brief this app
  was built against): Device Detail drawer, Traffic screen,
  network-map visualization, the appliance's own first-run setup wizard,
  DNS/blocklist/threat-intel admin screens, and true background APNs
  push. The architecture (one shared `AppSession`, one `HomeRadarClient`,
  one `DashboardSocket`) is intended to make adding these straightforward
  later without restructuring.

## Tests

`HomeRadarTests/` covers:

- `APIModelsDecodingTests.swift` -- fixture-based decoding of every
  `Codable` type, including the `is_resolved` int-vs-bool split, the
  fractional-second timestamp format, and unrecognized-key tolerance.
- `HomeRadarClientTests.swift` -- `URLProtocol`-stubbed request assertions
  (auth header, HTTP methods, JSON bodies) with no real network traffic.
- `DashboardSocketReconnectTests.swift` -- the pure `nextBackoffInterval`
  backoff schedule, no real socket or timers involved.
- `AlertDiffTests.swift` -- the pure `AlertDiffer` diff logic behind local
  notifications.

These were written by inspection to be correct against the documented
Swift/Foundation/XCTest APIs, but **have never been executed**. Run them
in Xcode (Cmd-U, or `xcodebuild test` from the command line on a Mac with
Xcode installed) before trusting them.
