import Foundation

/// Pure backoff schedule for websocket reconnect attempts.
func nextBackoffInterval(previous: TimeInterval) -> TimeInterval {
    let base: TimeInterval = 2.5
    let cap: TimeInterval = 15
    guard previous > 0 else { return base }
    return min(previous * 2, cap)
}

enum DashboardSocketState: Equatable {
    case disconnected
    case connecting
    case connected
}

/// Maintains an authenticated dashboard WebSocket and reconnects with capped
/// exponential backoff. Credentials are sent in the upgrade request header,
/// never in the URL.
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

    func start() {
        guard isStopped else { return }
        isStopped = false
        currentBackoff = 0
        connectOnce()
    }

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
            var request = URLRequest(url: try client.webSocketURL())
            request.timeoutInterval = 15
            client.attachAuth(&request)
            let newTask = session.webSocketTask(with: request)
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
            return
        }
        currentBackoff = 0
        onStateChange?(.connected)
        onSnapshot?(snapshot)
    }

    private func scheduleRetry() {
        guard !isStopped, retryTask == nil else { return }
        task = nil
        let wait = nextBackoffInterval(previous: currentBackoff)
        currentBackoff = wait
        retryTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
            guard let self, !Task.isCancelled, !self.isStopped else { return }
            self.retryTask = nil
            self.connectOnce()
        }
    }
}
