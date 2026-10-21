import XCTest
@testable import PassportCapture

final class CaptureGuideTests: XCTestCase {
    private func face(yaw: Double? = 0, pitch: Double? = 0, roll: Double? = 0, quality: Double? = 0.8,
                      bounds: CGRect = CGRect(x: 0.25, y: 0.25, width: 0.5, height: 0.5)) -> CaptureFace {
        CaptureFace(bounds: bounds, yaw: yaw, pitch: pitch, roll: roll, quality: quality)
    }
    @discardableResult private func hold(_ face: CaptureFace, guide: inout CaptureGuide, time: inout Double, samples: Int = 8) -> Int {
        var captured = 0
        for _ in 0..<samples {
            if guide.observe([face], at: time) { captured += 1; time += 0.65 }
            time += 0.1
        }
        return captured
    }
    func testRightThenLeftCapturesExactlyThreeFrames() {
        for direction in [-1.0] {
            var guide = CaptureGuide(); var time = 10.0
            XCTAssertEqual(hold(face(), guide: &guide, time: &time), 1)
            XCTAssertEqual(guide.guidance.pose, .side)
            XCTAssertEqual(hold(face(yaw: direction * 0.4), guide: &guide, time: &time), 1)
            XCTAssertEqual(guide.guidance.pose, .opposite)
            XCTAssertEqual(hold(face(yaw: direction * -0.4), guide: &guide, time: &time), 1)
            XCTAssertEqual(guide.guidance.completed, 3)
            XCTAssertEqual(guide.guidance.progress, 1)
            XCTAssertEqual(hold(face(), guide: &guide, time: &time, samples: 20), 0)
        }
    }
    func testStraightFaceCannotCompleteSideSteps() {
        var guide = CaptureGuide(); var time = 0.0
        XCTAssertEqual(hold(face(), guide: &guide, time: &time, samples: 80), 1)
        XCTAssertEqual(guide.guidance.completed, 1)
    }
    func testSameSideCannotCompleteOppositeStep() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time)
        XCTAssertEqual(hold(face(yaw: -0.4), guide: &guide, time: &time, samples: 80), 1)
        XCTAssertEqual(guide.guidance.completed, 2)
        XCTAssertEqual(guide.guidance.hint, CapturePose.opposite.title)
    }
    func testBriefPoseAndTooFewObservationsDoNotCapture() {
        var guide = CaptureGuide()
        for time in [0.0, 0.25, 0.5] { XCTAssertFalse(guide.observe([face()], at: time)) }
        XCTAssertTrue(guide.observe([face()], at: 0.75))
        var fresh = CaptureGuide(); var time = 0.0
        XCTAssertEqual(hold(face(), guide: &fresh, time: &time, samples: 3), 0)
        XCTAssertLessThan(fresh.guidance.holdProgress, 1)
    }
    func testMissingOrMultipleFacesResetHold() {
        for faces in [[], [face(), face()]] {
            var guide = CaptureGuide(); var time = 0.0
            hold(face(), guide: &guide, time: &time, samples: 4)
            XCTAssertFalse(guide.observe(faces, at: time)); time += 0.1
            XCTAssertEqual(guide.guidance.holdProgress, 0)
            XCTAssertFalse(guide.guidance.acceptable)
            XCTAssertEqual(hold(face(), guide: &guide, time: &time, samples: 4), 0)
        }
    }
    func testLongGapCannotCountAsStableHold() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time, samples: 4)
        XCTAssertFalse(guide.observe([face()], at: 5))
        XCTAssertEqual(guide.guidance.holdProgress, 0)
        XCTAssertEqual(guide.guidance.completed, 0)
    }
    func testRepeatedBackwardsAndNonFiniteTimestampsCannotAdvance() {
        var guide = CaptureGuide()
        for time in [1.0, 1, 1, 0, -1, Double.nan, .infinity] {
            XCTAssertFalse(guide.observe([face()], at: time))
        }
        XCTAssertEqual(guide.guidance.completed, 0)
        XCTAssertEqual(guide.guidance.holdProgress, 0)
    }
    func testMissingAnglesAndInvalidQualityFailClosed() {
        for input in [face(yaw: nil), face(pitch: nil), face(roll: nil), face(quality: nil),
                      face(yaw: .nan), face(pitch: .infinity), face(roll: -.infinity),
                      face(quality: .nan), face(quality: 1.1), face(quality: -0.1)] {
            var guide = CaptureGuide(); var time = 0.0
            XCTAssertEqual(hold(input, guide: &guide, time: &time, samples: 20), 0)
            XCTAssertFalse(guide.guidance.acceptable)
        }
    }
    func testDistanceCenteringAndClippedFaceRequireCorrection() {
        let boxes = [CGRect(x: 0.4, y: 0.4, width: 0.2, height: 0.2),
                     CGRect(x: 0.1, y: 0.1, width: 0.8, height: 0.8),
                     CGRect(x: 0, y: 0.25, width: 0.5, height: 0.5),
                     CGRect(x: 0.25, y: 0.5, width: 0.5, height: 0.5),
                     CGRect(x: -0.1, y: 0.1, width: 0.5, height: 0.5),
                     CGRect(x: 0.25, y: 0.25, width: 0, height: 0.5)]
        for box in boxes {
            var guide = CaptureGuide(); var time = 0.0
            XCTAssertEqual(hold(face(bounds: box), guide: &guide, time: &time, samples: 20), 0)
            XCTAssertFalse(guide.guidance.acceptable)
        }
    }
    func testTiltAndPoorQualityCannotBeCaptured() {
        for input in [face(pitch: 0.4), face(roll: -0.4), face(quality: 0.1)] {
            var guide = CaptureGuide(); var time = 0.0
            XCTAssertEqual(hold(input, guide: &guide, time: &time, samples: 20), 0)
        }
    }
    func testMovingWithinAllowedAnglesStillResetsHold() {
        var guide = CaptureGuide()
        for index in 0..<40 {
            XCTAssertFalse(guide.observe([face(yaw: index.isMultiple(of: 2) ? 0.12 : -0.12)], at: Double(index) * 0.1))
        }
        XCTAssertEqual(guide.guidance.completed, 0)
    }
    func testBriefPoorQualityPausesAndPersistentPoorQualityResets() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time)
        hold(face(yaw: -0.4), guide: &guide, time: &time, samples: 4)
        XCTAssertGreaterThan(guide.guidance.progress, 1.0 / 3)
        let saved = guide.guidance.progress
        XCTAssertFalse(guide.observe([face(yaw: -0.4, quality: 0.1)], at: time))
        XCTAssertEqual(guide.guidance.progress, saved)
        XCTAssertFalse(guide.guidance.acceptable)
        XCTAssertFalse(guide.observe([face(yaw: -0.4, quality: 0.1)], at: time + 0.2))
        XCTAssertEqual(guide.guidance.progress, 1.0 / 3, accuracy: 0.001)
        XCTAssertEqual(guide.guidance.completed, 1)
    }
    func testSideAngleBoundsPreventFullProfileAndTinyTurns() {
        for yaw in [0.1, -0.1, 0.7, -0.7] {
            var guide = CaptureGuide(); var time = 0.0
            hold(face(), guide: &guide, time: &time)
            XCTAssertEqual(hold(face(yaw: yaw), guide: &guide, time: &time, samples: 20), 0)
        }
    }
    func testSideFeedbackDistinguishesTooLittleAndTooMuchTurn() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time)
        for (yaw, message) in [(-0.1, "Vrid lite mer"), (-0.8, "Vrid tillbaka lite")] {
            XCTAssertFalse(guide.observe([face(yaw: yaw)], at: time)); time += 0.1
            XCTAssertTrue(guide.guidance.hint.hasPrefix(message))
            XCTAssertTrue(guide.guidance.distanceOK)
            XCTAssertTrue(guide.guidance.centered)
            XCTAssertFalse(guide.guidance.angleOK)
        }
    }
    func testSpatialFeedbackAvailableEvenWhenAngleOrQualityMissing() {
        var guide = CaptureGuide()
        XCTAssertFalse(guide.observe([face(yaw: nil, quality: nil,
            bounds: CGRect(x: 0.4, y: 0.4, width: 0.2, height: 0.2))], at: 0))
        XCTAssertEqual(guide.guidance.hint, "Flytta telefonen lite närmare")
        XCTAssertFalse(guide.guidance.distanceOK)
        XCTAssertTrue(guide.guidance.centered)
        XCTAssertFalse(guide.guidance.qualityOK)
        XCTAssertFalse(guide.guidance.angleOK)
        XCTAssertNotNil(guide.guidance.faceBounds)
        _ = guide.observe([], at: 0.1)
        XCTAssertNil(guide.guidance.faceBounds)
        XCTAssertFalse(guide.guidance.centered)
    }
    func testPreviewBoundsMirrorAndInvertVisionCoordinates() {
        var guidance = CaptureGuidance()
        guidance.faceBounds = CGRect(x: 0.1, y: 0.2, width: 0.3, height: 0.4)
        XCTAssertEqual(guidance.previewBounds!.minX, 0.6, accuracy: 0.001)
        XCTAssertEqual(guidance.previewBounds!.minY, 0.4, accuracy: 0.001)
        XCTAssertEqual(guidance.previewBounds!.width, 0.3, accuracy: 0.001)
    }

    func testNaturalSmallMovementsCanCompleteSideCapture() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time)
        var captures = 0
        for index in 0..<8 {
            let offset = index.isMultiple(of: 2) ? 0.015 : -0.015
            let input = face(yaw: index.isMultiple(of: 2) ? -0.35 : -0.45,
                             pitch: 0.25, roll: 0.25,
                             bounds: CGRect(x: 0.37 + offset, y: 0.25, width: 0.5, height: 0.5))
            if guide.observe([input], at: time) { captures += 1 }
            time += 0.1
        }
        XCTAssertEqual(captures, 1)
        XCTAssertEqual(guide.guidance.completed, 2)
    }
    func testLargePositionJumpsStillCannotCapture() {
        var guide = CaptureGuide()
        for index in 0..<20 {
            let x = index.isMultiple(of: 2) ? 0.18 : 0.32
            XCTAssertFalse(guide.observe([face(bounds: CGRect(x: x, y: 0.25, width: 0.5, height: 0.5))], at: Double(index) * 0.1))
        }
        XCTAssertEqual(guide.guidance.completed, 0)
    }

    func testPausedTimeNeverCountsTowardCapture() {
        var guide = CaptureGuide()
        for t in [0.0, 0.1, 0.2, 0.3] { XCTAssertFalse(guide.observe([face()], at: t)) }
        let progress = guide.guidance.holdProgress
        XCTAssertFalse(guide.observe([face(quality: 0.1)], at: 0.4))
        XCTAssertEqual(guide.guidance.holdProgress, progress)
        XCTAssertFalse(guide.observe([face()], at: 0.5))
        XCTAssertEqual(guide.guidance.holdProgress, progress)
        XCTAssertFalse(guide.observe([face()], at: 0.6))
        XCTAssertTrue(guide.observe([face()], at: 0.7))
        XCTAssertEqual(guide.guidance.confirmedPose, .front)
        XCTAssertFalse(guide.observe([face(yaw: -0.4)], at: 0.8))
        XCTAssertEqual(guide.guidance.confirmedPose, .front)
    }
    func testRepeatedDropoutsExhaustPauseAllowance() {
        var guide = CaptureGuide()
        for t in [0.0, 0.1, 0.2] { _ = guide.observe([face()], at: t) }
        _ = guide.observe([face(quality: 0.1)], at: 0.3)
        _ = guide.observe([face()], at: 0.4)
        _ = guide.observe([face(quality: 0.1)], at: 0.5)
        XCTAssertEqual(guide.guidance.holdProgress, 0)
        XCTAssertEqual(guide.guidance.completed, 0)
    }
    func testWrongDirectionCannotCaptureRightStep() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time)
        XCTAssertEqual(hold(face(yaw: 0.4), guide: &guide, time: &time, samples: 20), 0)
        XCTAssertEqual(guide.guidance.completed, 1)
        XCTAssertEqual(guide.guidance.hint, CapturePose.side.title)
    }

}
