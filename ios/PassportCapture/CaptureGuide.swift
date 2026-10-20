import Foundation
import CoreGraphics

enum CapturePose: Int, CaseIterable {
    case front, side, opposite

    var title: String {
        switch self {
        case .front: return "Titta rakt mot kameran"
        case .side: return "Vrid huvudet lite åt sidan"
        case .opposite: return "Vrid åt andra hållet"
        }
    }
    var shortTitle: String {
        switch self {
        case .front: return "Framåt"
        case .side: return "Ena sidan"
        case .opposite: return "Andra sidan"
        }
    }
}

struct CaptureFace {
    let bounds: CGRect
    let yaw: Double?
    let pitch: Double?
    let roll: Double?
    let quality: Double?
}

struct CaptureGuidance: Equatable {
    var pose: CapturePose = .front
    var completed = 0
    var holdProgress = 0.0
    var acceptable = false
    var hint = "Placera ansiktet i ovalen"
    var progress: Double { min(1, (Double(completed) + holdProgress) / 3) }
}

// Capture guidance only. These thresholds do not measure identity or liveness.
struct CaptureGuide {
    private(set) var guidance = CaptureGuidance()
    private var firstSide = 0.0
    private var stableSince: Double?
    private var previousTime: Double?
    private var previousFace: CaptureFace?
    private var samples = 0

    mutating func observe(_ faces: [CaptureFace], at time: Double) -> Bool {
        guard guidance.completed < 3 else { return false }
        guard time.isFinite else { resetHold("Håll telefonen stilla"); return false }
        if let previousTime, time <= previousTime || time - previousTime > 0.3 {
            resetHold("Håll telefonen stilla")
            if time <= previousTime { return false }
        }
        previousTime = time
        guard faces.count == 1 else {
            resetHold(faces.isEmpty ? "Placera ansiktet i ovalen" : "Bara ett ansikte får synas")
            return false
        }
        let face = faces[0]
        let box = face.bounds
        guard let yaw = face.yaw, let pitch = face.pitch, let roll = face.roll, let quality = face.quality,
              [yaw, pitch, roll, quality, Double(box.minX), Double(box.minY), Double(box.width), Double(box.height)].allSatisfy({ $0.isFinite }),
              (0...1).contains(quality), box.width > 0, box.height > 0,
              box.minX >= 0, box.minY >= 0, box.maxX <= 1, box.maxY <= 1 else {
            resetHold("Ansiktet behöver synas tydligare"); return false
        }
        if box.width < 0.32 || box.height < 0.32 { resetHold("Flytta telefonen lite närmare"); return false }
        if box.width > 0.72 || box.height > 0.62 { resetHold("Flytta telefonen lite längre bort"); return false }
        if abs(box.midX - 0.5) > 0.10 || abs(box.midY - 0.5) > 0.10 {
            resetHold("Placera ansiktet i ovalen"); return false
        }
        if abs(pitch) > 0.22 || abs(roll) > 0.22 { resetHold("Håll huvudet upprätt"); return false }
        if quality < 0.25 { resetHold("Sök bättre ljus och håll telefonen stilla"); return false }
        let correctPose: Bool
        switch guidance.pose {
        case .front: correctPose = abs(yaw) <= 0.14
        case .side: correctPose = (0.26...0.60).contains(abs(yaw))
        case .opposite: correctPose = (0.26...0.60).contains(abs(yaw)) && yaw * firstSide < 0
        }
        guard correctPose else { resetHold(guidance.pose.title); return false }
        if let previousFace, let previousYaw = previousFace.yaw, let previousPitch = previousFace.pitch, let previousRoll = previousFace.roll,
           abs(yaw - previousYaw) > 0.08 || abs(box.midX - previousFace.bounds.midX) > 0.025
            || abs(box.midY - previousFace.bounds.midY) > 0.025 || abs(box.width - previousFace.bounds.width) > 0.04
            || abs(box.height - previousFace.bounds.height) > 0.04 || abs(pitch - previousPitch) > 0.08 || abs(roll - previousRoll) > 0.08 {
            resetHold("Håll telefonen stilla")
        }
        previousFace = face
        if stableSince == nil { stableSince = time }
        samples += 1
        guidance.acceptable = true; guidance.hint = "Håll kvar"
        guidance.holdProgress = min(1, (time - stableSince!) / 0.65)
        guard guidance.holdProgress >= 1, samples >= 6 else { return false }
        if guidance.pose == .side { firstSide = yaw }
        guidance.completed += 1
        if guidance.completed < 3 { guidance.pose = CapturePose(rawValue: guidance.completed)! }
        resetHold(guidance.completed == 3 ? "Bilderna är tagna" : guidance.pose.title)
        return true
    }

    private mutating func resetHold(_ hint: String) {
        stableSince = nil; previousFace = nil; samples = 0
        guidance.holdProgress = 0; guidance.acceptable = false; guidance.hint = hint
    }
}
