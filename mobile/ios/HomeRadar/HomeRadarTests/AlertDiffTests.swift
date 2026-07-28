import XCTest
@testable import HomeRadar

/// NOTE: written by careful inspection of `AlertDiffer` in
/// `AlertDiff.swift`. NOT compiled or run -- no Swift toolchain exists in
/// the environment that authored this file.
final class AlertDiffTests: XCTestCase {
    private func makeAlert(id: Int, title: String? = nil) -> Alert {
        Alert(
            id: id,
            deviceId: nil,
            severity: "medium",
            title: title ?? "Alert \(id)",
            description: nil,
            isResolved: 0,
            createdAt: "2026-07-28T00:00:00.000000+00:00"
        )
    }

    func testFirstSnapshotEverFiresNothingButSeedsTheSeenSet() {
        var differ = AlertDiffer()
        let alerts = [makeAlert(id: 1), makeAlert(id: 2)]

        let firstResult = differ.newlyAppeared(in: alerts)
        XCTAssertTrue(firstResult.isEmpty, "the very first snapshot must never fire any notifications")

        // Feeding the exact same snapshot again must also report nothing --
        // this proves the first call actually seeded the seen set, rather
        // than just happening to have nothing new to report.
        let secondResult = differ.newlyAppeared(in: alerts)
        XCTAssertTrue(secondResult.isEmpty)
    }

    func testFirstEmptySnapshotSeedsAnEmptySeenSet() {
        var differ = AlertDiffer()
        XCTAssertTrue(differ.newlyAppeared(in: []).isEmpty)
        XCTAssertTrue(differ.seenAlertIDs.isEmpty)
    }

    func testNewIDOnSubsequentSnapshotIsReportedExactlyOnce() {
        var differ = AlertDiffer()
        _ = differ.newlyAppeared(in: [makeAlert(id: 1)]) // seed

        let withNewAlert = differ.newlyAppeared(in: [makeAlert(id: 1), makeAlert(id: 2)])
        XCTAssertEqual(withNewAlert.map(\.id), [2])

        // Re-delivering the same snapshot must not refire alert 2.
        let repeated = differ.newlyAppeared(in: [makeAlert(id: 1), makeAlert(id: 2)])
        XCTAssertTrue(repeated.isEmpty, "an already-seen alert must never be refired")
    }

    func testMultipleNewIDsInOneSnapshotAreAllReported() {
        var differ = AlertDiffer()
        _ = differ.newlyAppeared(in: [makeAlert(id: 1)]) // seed

        let result = differ.newlyAppeared(in: [makeAlert(id: 1), makeAlert(id: 2), makeAlert(id: 3)])
        XCTAssertEqual(Set(result.map(\.id)), Set([2, 3]))
    }

    func testDisappearingAlertCausesNoCrashAndIsNotRefiredIfItReappears() {
        var differ = AlertDiffer()
        _ = differ.newlyAppeared(in: [makeAlert(id: 1), makeAlert(id: 2)]) // seed

        // Alert 2 resolves and drops out of the live snapshot entirely.
        let afterResolve = differ.newlyAppeared(in: [makeAlert(id: 1)])
        XCTAssertTrue(afterResolve.isEmpty)

        // If an alert with the same ID were ever to reappear later, it's
        // already in the seen set and must not be treated as new.
        let reappeared = differ.newlyAppeared(in: [makeAlert(id: 1), makeAlert(id: 2)])
        XCTAssertTrue(reappeared.isEmpty)
    }

    func testEmptyFirstSnapshotThenPopulatedSnapshotReportsAllAsNew() {
        var differ = AlertDiffer()
        _ = differ.newlyAppeared(in: []) // seed with nothing

        let result = differ.newlyAppeared(in: [makeAlert(id: 5), makeAlert(id: 6)])
        XCTAssertEqual(Set(result.map(\.id)), Set([5, 6]))
    }
}
