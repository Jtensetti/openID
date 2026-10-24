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
    // Vision coordinates become top-left coordinates in the mirrored preview.
    var previewBounds: CGRect? {
        faceBounds.map { CGRect(x: 1 - $0.maxX, y: 1 - $0.maxY, width: $0.width, height: $0.height) }
    }
    var progress: Double { min(1, (Double(completed) + holdProgress) / 3) }
}

// Capture guidance only. These thresholds do not measure identity or liveness.
struct CaptureGuide {
    private(set) var guidance = CaptureGuidance()
    /// Order requested by the server for this session; the server checks the head turns in the frames.
    private let sequence: [CapturePose]
    init(sequence: [CapturePose] = CapturePose.allCases) {
        precondition(sequence.count == 3 && Set(sequence).count == 3, "Each pose exactly once")
        self.sequence = sequence
        guidance.pose = sequence[0]
        guidance.hint = sequence[0] == .front ? "Placera ansiktet i ovalen" : sequence[0].title
    }
    private var confirmationUntil = -Double.infinity
    private var heldDuration = 0.0
    private var lastAcceptedTime: Double?
    private var paused = false
    private var pauseBudget = 0.25
    private var previousTime: Double?
    private var previousFace: CaptureFace?
    private var samples = 0

    mutating func observe(_ faces: [CaptureFace], at time: Double) -> Bool {
        guard guidance.completed < 3 else { return false }
        if time.isFinite, time < confirmationUntil { return false }
        guidance.confirmedPose = nil
        guidance.faceBounds = nil
        guidance.distanceOK = false; guidance.centered = false
        guidance.angleOK = false; guidance.qualityOK = false
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
        guard [Double(box.minX), Double(box.minY), Double(box.width), Double(box.height)].allSatisfy({ $0.isFinite }),
              box.width > 0, box.height > 0, box.minX >= 0, box.minY >= 0, box.maxX <= 1, box.maxY <= 1 else {
            resetHold("Hela ansiktet behöver synas i bilden"); return false
        }
        guidance.faceBounds = box
        guidance.distanceOK = box.width >= 0.32 && box.height >= 0.32 && box.width <= 0.72 && box.height <= 0.62
        guidance.centered = abs(box.midX - 0.5) <= 0.14 && abs(box.midY - 0.5) <= 0.14
        guidance.qualityOK = face.quality.map { $0.isFinite && (0.25...1).contains($0) } ?? false
        let validAngles = [face.yaw, face.pitch, face.roll].allSatisfy { $0?.isFinite == true }
        let yaw = face.yaw ?? 0, pitch = face.pitch ?? 0, roll = face.roll ?? 0
        let poseHint: String?
        switch guidance.pose {
        case .front:
            poseHint = abs(yaw) <= 0.14 ? nil : "Vrid tillbaka mot kameran"
        case .side, .opposite:
            // Unmirrored portrait Vision input: negative yaw turns toward the
            // user's right (right in the mirrored preview).
            if abs(yaw) >= 0.26 && ((guidance.pose == .side && yaw > 0) || (guidance.pose == .opposite && yaw < 0)) { poseHint = guidance.pose.title }
            else if abs(yaw) < 0.26 { poseHint = "Vrid lite mer åt sidan – håll telefonen stilla" }
            else if abs(yaw) > 0.60 { poseHint = "Vrid tillbaka lite – inte hela vägen till profil" }
            else { poseHint = nil }
        }
        guidance.angleOK = validAngles && abs(pitch) <= 0.30 && abs(roll) <= 0.30 && poseHint == nil
        if box.width < 0.32 || box.height < 0.32 { pauseHold("Flytta telefonen lite närmare", at: time); return false }
        if box.width > 0.72 || box.height > 0.62 { pauseHold("Flytta telefonen lite längre bort", at: time); return false }
        if !guidance.centered { pauseHold("Flytta ansiktet till mitten av ovalen", at: time); return false }
        guard validAngles else { resetHold("Ansiktets vinkel kan inte avläsas – vänd dig lite mot kameran"); return false }
        if abs(roll) > 0.30 { pauseHold("Räta upp huvudet – luta inte åt axeln", at: time); return false }
        if abs(pitch) > 0.30 { pauseHold("Håll hakan rakt – inte uppåt eller nedåt", at: time); return false }
        if let poseHint {
            if abs(yaw) >= 0.26 { resetHold(poseHint) }
            else { pauseHold(poseHint, at: time) }
            return false
        }
        guard guidance.qualityOK else {
            let hint = "Bilden behöver bli tydligare – sök jämnt ljus och håll stilla"
            if let quality = face.quality, quality.isFinite, (0...1).contains(quality) { pauseHold(hint, at: time) }
            else { resetHold(hint) }
            return false
        }
        if let previousFace, let previousYaw = previousFace.yaw, let previousPitch = previousFace.pitch, let previousRoll = previousFace.roll,
           abs(yaw - previousYaw) > 0.14 || abs(box.midX - previousFace.bounds.midX) > 0.04
            || abs(box.midY - previousFace.bounds.midY) > 0.04 || abs(box.width - previousFace.bounds.width) > 0.06
            || abs(box.height - previousFace.bounds.height) > 0.06 || abs(pitch - previousPitch) > 0.14 || abs(roll - previousRoll) > 0.14 {
            resetHold("Håll telefonen stilla")
        }
        previousFace = face
        if let lastAcceptedTime {
            let elapsed = time - lastAcceptedTime
            if paused {
                if elapsed <= pauseBudget { pauseBudget -= elapsed }
                else { resetHold("Håll kvar") }
            } else { heldDuration += elapsed }
        }
        paused = false
        lastAcceptedTime = time
        samples += 1
        guidance.acceptable = true; guidance.hint = "Håll kvar"
        guidance.holdProgress = min(1, heldDuration / 0.45)
        guard guidance.holdProgress >= 1, samples >= 4 else { return false }
        let capturedPose = guidance.pose
        guidance.completed += 1
        if guidance.completed < 3 { guidance.pose = sequence[guidance.completed] }
        resetHold(guidance.completed == 3 ? "Bilderna är tagna" : guidance.pose.title)
        guidance.confirmedPose = capturedPose
        guidance.hint = "Bilden är tagen"
        confirmationUntil = time + 0.65
        return true
    }

    private mutating func pauseHold(_ hint: String, at time: Double) {
        guard let lastAcceptedTime, time - lastAcceptedTime <= pauseBudget else { resetHold(hint); return }
        paused = true
        guidance.acceptable = false
        guidance.hint = hint
    }

    private mutating func resetHold(_ hint: String) {
        heldDuration = 0; lastAcceptedTime = nil; paused = false; pauseBudget = 0.25
        previousFace = nil; samples = 0
        guidance.holdProgress = 0; guidance.acceptable = false; guidance.hint = hint
    }
}
