import XCTest
@testable import HomeRadar

/// NOTE: written by careful inspection of `nextBackoffInterval` in
/// `DashboardSocket.swift`. NOT compiled or run -- no Swift toolchain
/// exists in the environment that authored this file.
///
/// Exercises `nextBackoffInterval` as a pure function only -- no real
/// socket, no timers, no `Task.sleep`.
final class DashboardSocketReconnectTests: XCTestCase {
    func testFirstCallFromZeroReturnsBaseDelay() {
        XCTAssertEqual(nextBackoffInterval(previous: 0), 2.5)
    }

    func testNegativePreviousIsTreatedAsUninitializedAndReturnsBaseDelay() {
        XCTAssertEqual(nextBackoffInterval(previous: -1), 2.5)
    }

    func testFullProgressionDoublesThenCapsAtFifteen() {
        var interval: TimeInterval = 0

        interval = nextBackoffInterval(previous: interval)
        XCTAssertEqual(interval, 2.5)

        interval = nextBackoffInterval(previous: interval)
        XCTAssertEqual(interval, 5)

        interval = nextBackoffInterval(previous: interval)
        XCTAssertEqual(interval, 10)

        interval = nextBackoffInterval(previous: interval)
        XCTAssertEqual(interval, 15, "20s would exceed the 15s cap")

        interval = nextBackoffInterval(previous: interval)
        XCTAssertEqual(interval, 15, "already at the cap, must stay at the cap")

        interval = nextBackoffInterval(previous: interval)
        XCTAssertEqual(interval, 15, "repeated calls at the cap must remain stable, not drift")
    }

    func testResettingToZeroAfterCapReturnsToBaseDelay() {
        // Simulates: connection was retried up to the 15s cap, then a
        // snapshot succeeded and `DashboardSocket` resets its tracked
        // interval to 0 (see `handle(_:)`) before the next disconnect.
        let afterSuccessReset: TimeInterval = 0
        XCTAssertEqual(nextBackoffInterval(previous: afterSuccessReset), 2.5)
    }
}
