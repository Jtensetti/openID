import Foundation
import CoreGraphics

enum CapturePose: Int, CaseIterable {
    case front, side, opposite

    var title: String {
        switch self {
        case .front: return "Titta rakt mot kameran"
        case .side: return "Vrid huvudet lite åt höger"
        case .opposite: return "Vrid huvudet lite åt vänster"
        }
    }
    var shortTitle: String {
        switch self {
        case .front: return "Framåt"
        case .side: return "Höger"
        case .opposite: return "Vänster"
        }
    }
    /// Server names: "right" is a turn to the user's own right (.side), "left" to the left (.opposite).
    init?(server: String) {
        switch server {
        case "front": self = .front
        case "right": self = .side
        case "left": self = .opposite
        default: return nil
        }
    }
    /// The server's random order after the chip check; each pose exactly once. Older servers send none.
    static func sequence(server: [String]?) -> [CapturePose]? {
        guard let server else { return CapturePose.allCases }
        let poses = server.compactMap(CapturePose.init(server:))
        guard poses.count == 3, Set(poses).count == 3, server.count == 3 else { return nil }
        return poses
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
    var confirmedPose: CapturePose?
    var completed = 0
    var holdProgress = 0.0
    var acceptable = false
    var hint = "Placera ansiktet i ovalen"
    var faceBounds: CGRect?
    var distanceOK = false
    var centered = false
    var angleOK = false
    var qualityOK = false
    var proximity = 0.0
    var completedPoses: Set<CapturePose> = []
    var sequence: [CapturePose] = CapturePose.allCases
    // Vision coordinates become top-left coordinates in the mirrored preview.
    var previewBounds: CGRect? {
        faceBounds.map { CGRect(x: 1 - $0.maxX, y: 1 - $0.maxY, width: $0.width, height: $0.height) }
    }
    var progress: Double { min(1, (Double(completed) + holdProgress) / 3) }
}

// Local composition/quality guidance, never an identity or liveness decision.
struct CaptureGuide {
    static let captureDuration = 0.18
    static let confirmationDuration = 0.30
    private(set) var guidance = CaptureGuidance()
    // These generations also invalidate camera bytes, not just the UI progress.
    private(set) var candidateGeneration = 0
    private(set) var sessionGeneration = 0
    private(set) var candidateEligible = false
    private let sequence: [CapturePose]
    private var confirmationUntil = -Double.infinity
    private var heldDuration = 0.0
    private var lastAcceptedTime: Double?
    private var candidateStarted: Double?
    private var paused = false
    private var pauseBudget = 0.25
    private var previousTime: Double?
    private var lastFaceTime: Double?
    private var previousFace: CaptureFace?
    private var samples = 0
    private var pendingHint: String?
    private var pendingHintSince = 0.0

    init(sequence: [CapturePose] = CapturePose.allCases) {
        precondition(sequence.count == 3 && Set(sequence).count == 3, "Each pose exactly once")
        self.sequence = sequence
        guidance.sequence = sequence
        guidance.pose = sequence[0]
        guidance.hint = sequence[0] == .front ? "Placera ansiktet i ovalen" : sequence[0].title
    }

    mutating func observe(_ faces: [CaptureFace], at time: Double) -> Bool {
        candidateEligible = false
        guard guidance.completed < 3 else { return false }
        guidance.acceptable = false
        guidance.faceBounds = nil
        guidance.distanceOK = false; guidance.centered = false
        guidance.angleOK = false; guidance.qualityOK = false; guidance.proximity = 0
        guard time.isFinite else { resetWindow(); return false }
        if let previousTime {
            guard time > previousTime else { resetWindow(); return false }
            if time - previousTime > 1 { restart() }
            else if time - previousTime > 0.3 { resetWindow() }
        }
        previousTime = time
        guard faces.count == 1 else {
            resetWindow()
            if faces.count > 1 || lastFaceTime.map({ time - $0 > 1 }) == true { restart() }
            setHint(faces.isEmpty ? "Placera ansiktet i ovalen" : "Bara ett ansikte får synas", at: time, immediate: true)
            return false
        }
        if let lastFaceTime, time - lastFaceTime > 1 { restart() }
        let face = faces[0], box = faces[0].bounds
        guard [Double(box.minX), Double(box.minY), Double(box.width), Double(box.height)].allSatisfy({ $0.isFinite }),
              box.width > 0, box.height > 0, box.minX >= 0, box.minY >= 0, box.maxX <= 1, box.maxY <= 1 else {
            resetWindow(); setHint("Hela ansiktet behöver synas", at: time, immediate: true); return false
        }
        lastFaceTime = time
        // Continue checking presence during the short confirmation; no frame from it is reused.
        if time < confirmationUntil { return false }
        if guidance.confirmedPose != nil {
            guidance.confirmedPose = nil
            resetWindow()
            setHint(guidance.pose.title, at: time, immediate: true)
        }
        guidance.faceBounds = box
        guidance.distanceOK = box.width >= 0.32 && box.height >= 0.32 && box.width <= 0.72 && box.height <= 0.62
        guidance.centered = abs(box.midX - 0.5) <= 0.14 && abs(box.midY - 0.5) <= 0.14
        guidance.qualityOK = face.quality.map { $0.isFinite && (0.25...1).contains($0) } ?? false
        let validAngles = [face.yaw, face.pitch, face.roll].allSatisfy { $0?.isFinite == true }
        let yaw = face.yaw ?? 0, pitch = face.pitch ?? 0, roll = face.roll ?? 0
        let turn = guidance.pose == .side ? -yaw : yaw
        let poseHint: String?
        if guidance.pose == .front {
            poseHint = abs(yaw) <= 0.14 ? nil : "Vrid tillbaka mot kameran"
        } else if turn < 0 {
            poseHint = guidance.pose.title
        } else if turn < 0.26 {
            poseHint = "Vrid lite till"
        } else if turn > 0.60 {
            poseHint = "Vrid tillbaka lite"
        } else { poseHint = nil }
        guidance.angleOK = validAngles && abs(pitch) <= 0.30 && abs(roll) <= 0.30 && poseHint == nil
        if validAngles {
            let angle = guidance.pose == .front
                ? closeness(abs(yaw), to: 0...0.14, margin: 0.45)
                : closeness(turn, to: 0.26...0.60, margin: 0.26)
            guidance.proximity = min(angle,
                closeness(Double(box.width), to: 0.32...0.72, margin: 0.25),
                closeness(Double(box.height), to: 0.32...0.62, margin: 0.25),
                closeness(Double(abs(box.midX - 0.5)), to: 0...0.14, margin: 0.25),
                closeness(Double(abs(box.midY - 0.5)), to: 0...0.14, margin: 0.25),
                closeness(abs(pitch), to: 0...0.30, margin: 0.30),
                closeness(abs(roll), to: 0...0.30, margin: 0.30))
        }
        let correction: String?
        if box.width < 0.32 || box.height < 0.32 { correction = "Lite närmare" }
        else if box.width > 0.72 || box.height > 0.62 { correction = "Lite längre bort" }
        else if !guidance.centered { correction = "Flytta ansiktet till mitten av ovalen" }
        else if !validAngles { correction = "Vänd ansiktet lite mot kameran" }
        else if abs(roll) > 0.30 { correction = "Räta upp huvudet lite" }
        else if abs(pitch) > 0.30 { correction = "Håll hakan rakt" }
        else if let poseHint { correction = poseHint }
        else if !guidance.qualityOK { correction = "Sök jämnt ljus på ansiktet" }
        else { correction = nil }
        if let correction {
            pauseWindow(at: time)
            setHint(correction, at: time)
            return false
        }
        // Natural motion is allowed; discontinuous jumps cannot build a candidate window.
        if let previousFace, let previousYaw = previousFace.yaw,
           abs(yaw - previousYaw) > 0.20 || abs(box.midX - previousFace.bounds.midX) > 0.08
            || abs(box.midY - previousFace.bounds.midY) > 0.08 || abs(box.width - previousFace.bounds.width) > 0.10
            || abs(box.height - previousFace.bounds.height) > 0.10 {
            resetWindow()
        }
        if let candidateStarted, time - candidateStarted > 0.50 { resetWindow() }
        previousFace = face
        if let lastAcceptedTime {
            let elapsed = time - lastAcceptedTime
            if paused {
                if elapsed <= pauseBudget { pauseBudget -= elapsed }
                else { resetWindow() }
            } else { heldDuration += elapsed }
        }
        if candidateStarted == nil { candidateStarted = time }
        paused = false; lastAcceptedTime = time; samples += 1
        candidateEligible = true
        guidance.acceptable = true
        setHint("Bra, bilden tas automatiskt", at: time)
        guidance.holdProgress = min(1, heldDuration / Self.captureDuration)
        guard heldDuration + 0.000001 >= Self.captureDuration, samples >= 3 else { return false }
        let capturedPose = guidance.pose
        guidance.completed += 1
        guidance.completedPoses.insert(capturedPose)
        if guidance.completed < 3 { guidance.pose = sequence[guidance.completed] }
        guidance.holdProgress = 0
        guidance.confirmedPose = capturedPose
        setHint(guidance.completed == 3 ? "Bilderna är tagna" : "Bilden är tagen", at: time, immediate: true)
        confirmationUntil = time + Self.confirmationDuration
        return true
    }

    private func closeness(_ value: Double, to range: ClosedRange<Double>, margin: Double) -> Double {
        max(0, 1 - max(range.lowerBound - value, value - range.upperBound, 0) / margin)
    }
    private mutating func pauseWindow(at time: Double) {
        guard let lastAcceptedTime, time - lastAcceptedTime <= pauseBudget else { resetWindow(); return }
        paused = true
    }
    private mutating func resetWindow() {
        heldDuration = 0; lastAcceptedTime = nil; candidateStarted = nil; paused = false; pauseBudget = 0.25
        previousFace = nil; samples = 0; candidateGeneration += 1
        guidance.holdProgress = 0; guidance.acceptable = false; candidateEligible = false
    }
    private mutating func restart() {
        resetWindow(); sessionGeneration += 1; lastFaceTime = nil
        guidance.completed = 0; guidance.completedPoses = []; guidance.pose = sequence[0]
        guidance.confirmedPose = nil; confirmationUntil = -.infinity
    }
    private mutating func setHint(_ hint: String, at time: Double, immediate: Bool = false) {
        if immediate || previousTime == nil || guidance.faceBounds == nil {
            guidance.hint = hint; pendingHint = nil; return
        }
        if hint == guidance.hint { pendingHint = nil; return }
        if pendingHint != hint { pendingHint = hint; pendingHintSince = time }
        if time - pendingHintSince >= 0.22 { guidance.hint = hint; pendingHint = nil }
    }
}

/// Keeps only the best encoded frame in the current short window. No camera buffers escape their callback.
struct CaptureCandidate<Value> {
    private(set) var value: Value?
    private var quality = -Double.infinity
    private var generation = -1
    mutating func reset(to generation: Int) {
        guard self.generation != generation else { return }
        self.generation = generation; value = nil; quality = -.infinity
    }
    mutating func consider(quality: Double, makeValue: () throws -> Value) rethrows {
        guard quality.isFinite, (0.25...1).contains(quality), quality > self.quality else { return }
        value = try makeValue(); self.quality = quality
    }
}
