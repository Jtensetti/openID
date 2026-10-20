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
            if guide.observe([face], at: time) { captured += 1 }
            time += 0.1
        }
        return captured
    }
    func testBothOrdersCaptureExactlyThreeFrames() {
        for direction in [-1.0, 1.0] {
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
        XCTAssertEqual(hold(face(yaw: 0.4), guide: &guide, time: &time, samples: 80), 1)
        XCTAssertEqual(guide.guidance.completed, 2)
        XCTAssertEqual(guide.guidance.hint, CapturePose.opposite.title)
    }
    func testBriefPoseAndTooFewObservationsDoNotCapture() {
        var guide = CaptureGuide()
        for time in [0.0, 0.2, 0.4, 0.6, 0.8] { XCTAssertFalse(guide.observe([face()], at: time)) }
        XCTAssertTrue(guide.observe([face()], at: 1.0))
        var fresh = CaptureGuide(); var time = 0.0
        XCTAssertEqual(hold(face(), guide: &fresh, time: &time, samples: 6), 0)
        XCTAssertLessThan(fresh.guidance.holdProgress, 1)
    }
    func testMissingOrMultipleFacesResetHold() {
        for faces in [[], [face(), face()]] {
            var guide = CaptureGuide(); var time = 0.0
            hold(face(), guide: &guide, time: &time, samples: 5)
            XCTAssertFalse(guide.observe(faces, at: time)); time += 0.1
            XCTAssertEqual(guide.guidance.holdProgress, 0)
            XCTAssertFalse(guide.guidance.acceptable)
            XCTAssertEqual(hold(face(), guide: &guide, time: &time, samples: 5), 0)
        }
    }
    func testLongGapCannotCountAsStableHold() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time, samples: 5)
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
        for input in [face(pitch: 0.3), face(roll: -0.3), face(quality: 0.1)] {
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
    func testBadFrameResetsOnlyCurrentStepAndProgressNeverRegressesPastCapturedFrame() {
        var guide = CaptureGuide(); var time = 0.0
        hold(face(), guide: &guide, time: &time)
        hold(face(yaw: 0.4), guide: &guide, time: &time, samples: 5)
        XCTAssertGreaterThan(guide.guidance.progress, 1.0 / 3)
        XCTAssertFalse(guide.observe([face(yaw: 0.4, quality: 0.1)], at: time))
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
}
