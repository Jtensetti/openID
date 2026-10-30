import XCTest
@testable import PassportCapture

final class CaptureGuideTests: XCTestCase {
    private func face(yaw: Double? = 0, pitch: Double? = 0, roll: Double? = 0, quality: Double? = 0.8,
                      bounds: CGRect = CGRect(x: 0.25, y: 0.25, width: 0.5, height: 0.5)) -> CaptureFace {
        CaptureFace(bounds: bounds, yaw: yaw, pitch: pitch, roll: roll, quality: quality)
    }
    private func capture(_ pose: CapturePose, guide: inout CaptureGuide, time: inout Double) {
        let yaw = pose == .front ? 0.0 : (pose == .side ? -0.4 : 0.4)
        var count = 0
        for _ in 0..<10 {
            let captured = guide.observe([face(yaw: yaw)], at: time)
            time += 0.09
            if captured { count += 1; time += 0.31; break }
        }
        XCTAssertEqual(count, 1)
    }
    func testThreeQuickCapturesFollowEveryServerPermutation() {
        let orders: [[CapturePose]] = [[.front, .side, .opposite], [.front, .opposite, .side],
            [.side, .front, .opposite], [.side, .opposite, .front], [.opposite, .front, .side], [.opposite, .side, .front]]
        for order in orders {
            var guide = CaptureGuide(sequence: order); var time = 0.0
            for pose in order {
                XCTAssertEqual(guide.guidance.pose, pose)
                capture(pose, guide: &guide, time: &time)
                XCTAssertTrue(guide.guidance.completedPoses.contains(pose))
            }
            XCTAssertEqual(guide.guidance.completed, 3)
            XCTAssertEqual(guide.guidance.progress, 1)
            XCTAssertEqual(guide.guidance.hint, "Bilderna är tagna")
            XCTAssertLessThan(time, 2.0) // Synthetic ideal observations, not a phone/user timing claim.
            XCTAssertFalse(guide.observe([face()], at: time))
        }
    }
    func testServerOrderValidation() {
        XCTAssertEqual(CapturePose.sequence(server: ["left", "front", "right"]), [.opposite, .front, .side])
        XCTAssertEqual(CapturePose.sequence(server: nil), CapturePose.allCases)
        for invalid in [["front", "front", "left"], ["front", "right"], ["front", "right", "left", "front"], ["front", "up", "left"]] {
            XCTAssertNil(CapturePose.sequence(server: invalid))
        }
    }
    func testOneFrameOrTwoFramesCannotCaptureEvenIfTimePassed() {
        var guide = CaptureGuide()
        XCTAssertFalse(guide.observe([face()], at: 0))
        XCTAssertFalse(guide.observe([face()], at: 0.2))
        XCTAssertTrue(guide.observe([face()], at: 0.26))
        var brief = CaptureGuide()
        for t in [0.0, 0.01, 0.02, 0.03] { XCTAssertFalse(brief.observe([face()], at: t)) }
    }
    func testNaturalMovementThroughTargetCanCapture() {
        var guide = CaptureGuide(sequence: [.side, .front, .opposite])
        XCTAssertFalse(guide.observe([face(yaw: -0.26, pitch: 0.25, roll: 0.25)], at: 0))
        XCTAssertFalse(guide.observe([face(yaw: -0.35, pitch: 0.25, roll: 0.25)], at: 0.09))
        XCTAssertTrue(guide.observe([face(yaw: -0.45, pitch: 0.25, roll: 0.25)], at: 0.18))
    }
    func testWrongSideTinyTurnAndFullProfileNeverCapture() {
        for yaw in [0.0, 0.4, -0.1, -0.7] {
            var guide = CaptureGuide(sequence: [.side, .front, .opposite])
            for index in 0..<20 { XCTAssertFalse(guide.observe([face(yaw: yaw)], at: Double(index) * 0.09)) }
            XCTAssertEqual(guide.guidance.completed, 0)
        }
    }
    func testCompletedSideCannotBeUsedForOppositeSide() {
        var guide = CaptureGuide(sequence: [.side, .opposite, .front]); var time = 0.0
        capture(.side, guide: &guide, time: &time)
        for _ in 0..<20 {
            XCTAssertFalse(guide.observe([face(yaw: -0.4)], at: time)); time += 0.09
        }
        XCTAssertEqual(guide.guidance.completedPoses, [.side])
    }
    func testProximityTracksDirectionAndOvershootWithoutWaiting() {
        for pose in [CapturePose.side, .opposite] {
            var guide = CaptureGuide(sequence: [pose, .front, pose == .side ? .opposite : .side])
            let sign = pose == .side ? -1.0 : 1.0
            var previous = -1.0
            for (i, angle) in [0.0, 0.065, 0.13, 0.195, 0.26].enumerated() {
                _ = guide.observe([face(yaw: angle * sign)], at: Double(i) * 0.06)
                XCTAssertGreaterThan(guide.guidance.proximity, previous)
                previous = guide.guidance.proximity
            }
            XCTAssertEqual(guide.guidance.proximity, 1)
            _ = guide.observe([face(yaw: 0.75 * sign)], at: 0.30)
            XCTAssertLessThan(guide.guidance.proximity, 0.5)
            _ = guide.observe([face(yaw: -0.3 * sign)], at: 0.36)
            XCTAssertEqual(guide.guidance.proximity, 0)
        }
    }
    func testLowQualityCannotTurnFullGeometryIntoCapture() {
        var guide = CaptureGuide()
        for i in 0..<20 { XCTAssertFalse(guide.observe([face(quality: 0.1)], at: Double(i) * 0.09)) }
        XCTAssertEqual(guide.guidance.proximity, 1)
        XCTAssertFalse(guide.guidance.acceptable)
        XCTAssertFalse(guide.candidateEligible)
    }
    func testMissingAnglesInvalidQualityAndTiltFailClosed() {
        for input in [face(yaw: nil), face(pitch: nil), face(roll: nil), face(quality: nil),
                      face(yaw: .nan), face(pitch: .infinity), face(roll: -.infinity),
                      face(quality: .nan), face(quality: 1.1), face(quality: -0.1), face(pitch: 0.4), face(roll: -0.4)] {
            var guide = CaptureGuide()
            for i in 0..<20 { XCTAssertFalse(guide.observe([input], at: Double(i) * 0.09)) }
            XCTAssertFalse(guide.candidateEligible)
        }
    }
    func testDistanceCenteringAndClippingRequireCorrection() {
        for box in [CGRect(x: 0.4, y: 0.4, width: 0.2, height: 0.2), CGRect(x: 0.1, y: 0.1, width: 0.8, height: 0.8),
                    CGRect(x: 0, y: 0.25, width: 0.5, height: 0.5), CGRect(x: 0.25, y: 0.5, width: 0.5, height: 0.5),
                    CGRect(x: -0.1, y: 0.1, width: 0.5, height: 0.5), CGRect(x: 0.25, y: 0.25, width: 0, height: 0.5)] {
            var guide = CaptureGuide()
            for i in 0..<20 { XCTAssertFalse(guide.observe([face(bounds: box)], at: Double(i) * 0.09)) }
            XCTAssertFalse(guide.guidance.acceptable)
        }
    }
    func testLargePositionAndAngleJumpsResetCandidateWindow() {
        for movement in [true, false] {
            var guide = CaptureGuide()
            for i in 0..<20 {
                let x = movement ? (i.isMultiple(of: 2) ? 0.18 : 0.32) : 0.25
                let yaw = movement ? 0 : (i.isMultiple(of: 2) ? 0.12 : -0.12)
                XCTAssertFalse(guide.observe([face(yaw: yaw, bounds: CGRect(x: x, y: 0.25, width: 0.5, height: 0.5))], at: Double(i) * 0.09))
            }
        }
    }
    func testBriefDipPausesWithoutCountingBadFramesOrFlickeringHint() {
        var guide = CaptureGuide()
        _ = guide.observe([face()], at: 0)
        _ = guide.observe([face()], at: 0.09)
        let progress = guide.guidance.holdProgress, hint = guide.guidance.hint, generation = guide.candidateGeneration
        XCTAssertFalse(guide.observe([face(quality: 0.1)], at: 0.12))
        XCTAssertEqual(guide.guidance.holdProgress, progress)
        XCTAssertEqual(guide.guidance.hint, hint)
        XCTAssertFalse(guide.candidateEligible)
        XCTAssertFalse(guide.observe([face()], at: 0.20))
        XCTAssertEqual(guide.guidance.holdProgress, progress)
        XCTAssertEqual(guide.candidateGeneration, generation)
        XCTAssertTrue(guide.observe([face()], at: 0.29))
    }
    func testPersistentDipInvalidatesCandidateButPreservesFinishedStep() {
        var guide = CaptureGuide(); var time = 0.0
        capture(.front, guide: &guide, time: &time)
        _ = guide.observe([face(yaw: -0.4)], at: time)
        let generation = guide.candidateGeneration
        _ = guide.observe([face(yaw: -0.4, quality: 0.1)], at: time + 0.1)
        _ = guide.observe([face(yaw: -0.4, quality: 0.1)], at: time + 0.3)
        XCTAssertGreaterThan(guide.candidateGeneration, generation)
        XCTAssertEqual(guide.guidance.completedPoses, [.front])
        XCTAssertEqual(guide.guidance.holdProgress, 0)
    }
    func testMultipleFacesInvalidateAllCapturedFramesEvenDuringConfirmation() {
        var guide = CaptureGuide(); var time = 0.0
        capture(.front, guide: &guide, time: &time)
        let generation = guide.sessionGeneration
        _ = guide.observe([face(), face()], at: time - 0.30)
        XCTAssertGreaterThan(guide.sessionGeneration, generation)
        XCTAssertEqual(guide.guidance.completed, 0)
        XCTAssertNil(guide.guidance.confirmedPose)
    }
    func testShortFaceLossPreservesStepsButLongLossRestarts() {
        var guide = CaptureGuide(); var time = 0.0
        capture(.front, guide: &guide, time: &time)
        _ = guide.observe([], at: time)
        XCTAssertEqual(guide.guidance.completed, 1)
        _ = guide.observe([face(yaw: -0.4)], at: time + 0.1)
        XCTAssertEqual(guide.guidance.completed, 1)
        for i in 1...12 { _ = guide.observe([], at: time + 0.1 + Double(i) * 0.1) }
        XCTAssertEqual(guide.guidance.completed, 0)
        XCTAssertGreaterThan(guide.sessionGeneration, 0)
    }
    func testLongTimestampGapAndNonMonotonicTimesCannotReuseCandidates() {
        var guide = CaptureGuide()
        _ = guide.observe([face()], at: 0)
        _ = guide.observe([face()], at: 0.09)
        for t in [0.09, 0.0, Double.nan, .infinity, 5.0] {
            XCTAssertFalse(guide.observe([face()], at: t))
            XCTAssertEqual(guide.guidance.holdProgress, 0)
        }
        XCTAssertGreaterThan(guide.sessionGeneration, 0)
    }
    func testBestFrameIsSelectedAndOldGenerationCannotLeak() {
        var guide = CaptureGuide(); var candidate = CaptureCandidate<String>()
        for (i, quality) in [0.9, 0.3, 0.5].enumerated() {
            let done = guide.observe([face(quality: quality)], at: Double(i) * 0.09)
            candidate.reset(to: guide.candidateGeneration)
            if guide.candidateEligible { candidate.consider(quality: quality) { "frame-\(i)" } }
            if done { XCTAssertEqual(candidate.value, "frame-0") }
        }
        XCTAssertEqual(guide.guidance.completed, 1)
        _ = guide.observe([face(yaw: -0.4, quality: 0.1)], at: 0.6)
        candidate.reset(to: guide.candidateGeneration)
        XCTAssertNil(candidate.value)
        candidate.consider(quality: .nan) { XCTFail("Invalid quality must not encode"); return "invalid" }
        XCTAssertNil(candidate.value)
    }
    func testPreviewBoundsMirrorAndInvertVisionCoordinates() {
        var guidance = CaptureGuidance()
        guidance.faceBounds = CGRect(x: 0.1, y: 0.2, width: 0.3, height: 0.4)
        XCTAssertEqual(guidance.previewBounds!.minX, 0.6, accuracy: 0.001)
        XCTAssertEqual(guidance.previewBounds!.minY, 0.4, accuracy: 0.001)
    }
}
