import Foundation

/// Pure backoff schedule for websocket reconnect attempts.
///
/// Progression: 2.5s -> 5s -> 10s -> capped at 15s, resetting to 2.5s after
/// any successful snapshot. `previous <= 0` is treated as "no attempt yet"
/// and returns the base 2.5s delay.
///
/// This is deliberately more aggressive than the web dashboard's flat retry
/// interval -- not a bug. Mobile networks (switching Wi-Fi/cellular,
/// backgrounding, walking out of range of the LAN appliance) drop far more
/// often than a wired browser session, so a capped exponential backoff
/// recovers quickly from the common case (a brief blip) while still not
/// hammering the appliance during a prolonged outage.
func nextBackoffInterval(previous: TimeInterval) -> TimeInterval {
    let base: TimeInterval = 2.5
    let cap: TimeInterval = 15
    guard previous > 0 else { return base }
    return min(previous * 2, cap)
}

/// Coarse connection state for UI (e.g. a "Live"/"Connecting"/"Disconnected"
/// indicator on the Overview screen).
enum DashboardSocketState: Equatable {
    case disconnected
    case connecting
    case connected
}

/// Maintains a persistent connection to `GET /ws`, decoding each pushed
/// `snapshot` text frame and forwarding it via `onSnapshot`.
///
/// The server never pings, never explicitly closes, and needs no message
/// from the client to keep pushing -- so noticing a dropped connection and
/// reconnecting (with backoff, see `nextBackoffInterval`) is entirely this
/// class's job.
final class DashboardSocket {
    var onSnapshot: ((SnapshotMessage) -> Void)?
    var onStateChange: ((DashboardSocketState) -> Void)?

    private let client: HomeRadarClient
    private let session: URLSession
    private static let decoder = JSONDecoder()

    private var task: URLSessionWebSocketTask?
    private var receiveLoopTask: Task<Void, Never>?
    private var retryTask: Task<Void, Never>?
    private var currentBackoff: TimeInterval = 0
    private var isStopped = true

    init(client: HomeRadarClient, session: URLSession = .shared) {
        self.client = client
        self.session = session
    }

    /// Starts (or restarts) the connect/reconnect loop. Safe to call again
    /// after `stop()`, e.g. when the app returns to the foreground. A no-op
    /// if already running.
    func start() {
        guard isStopped else { return }
        isStopped = false
        currentBackoff = 0
        connectOnce()
    }

    /// Tears down the socket and cancels any pending reconnect attempt.
    /// Call this when the app backgrounds (`scenePhase == .background`).
    func stop() {
        isStopped = true
        retryTask?.cancel()
        retryTask = nil
        receiveLoopTask?.cancel()
        receiveLoopTask = nil
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        onStateChange?(.disconnected)
    }

    private func connectOnce() {
        guard !isStopped else { return }
        onStateChange?(.connecting)
        do {
            let url = try client.webSocketURL()
            let newTask = session.webSocketTask(with: url)
            task = newTask
            newTask.resume()
            listen(on: newTask)
        } catch {
            scheduleRetry()
        }
    }

    private func listen(on task: URLSessionWebSocketTask) {
        receiveLoopTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                do {
                    let message = try await task.receive()
                    self.handle(message)
                } catch {
                    if Task.isCancelled || self.isStopped { return }
                    self.onStateChange?(.disconnected)
                    self.scheduleRetry()
                    return
                }
            }
        }
    }

    private func handle(_ message: URLSessionWebSocketTask.Message) {
        let data: Data?
        switch message {
        case .data(let raw):
            data = raw
        case .string(let text):
            data = Data(text.utf8)
        @unknown default:
            data = nil
        }
        guard let data, let snapshot = try? Self.decoder.decode(SnapshotMessage.self, from: data) else {
            // Malformed/unrecognized frame: ignore it, keep listening. Don't
            // tear down the connection over one bad frame.
            return
        }
        // A successfully parsed snapshot is this class's definition of a
        // "successful" connection for backoff-reset purposes.
        currentBackoff = 0
        onStateChange?(.connected)
        onSnapshot?(snapshot)
    }

    private func scheduleRetry() {
        guard !isStopped else { return }
        task = nil
        let wait = nextBackoffInterval(previous: currentBackoff)
        currentBackoff = wait
        retryTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
            guard let self, !Task.isCancelled, !self.isStopped else { return }
            self.connectOnce()
        }
    }
}
