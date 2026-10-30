import SwiftUI
import VisionKit
import AVFoundation
import Vision
import CoreImage

struct PassportScanView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var authorized = false
    @State private var message = "Placera hela passets porträttsida i ramen"
    @State private var captured = false
    let onRead: (PassportMRZ) -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    if authorized && DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                        GeometryReader { geometry in
                            let frame = PassportPageFrame.rect(in: geometry.size)
                            ZStack {
                                MRZCamera(pageFrame: frame, onRead: { value in onRead(value); dismiss() }, onGuidance: { text, ready in
                                    message = text; captured = ready
                                }, onFailure: {
                                    message = "Kameraläsningen är inte tillgänglig. Stäng och fyll i uppgifterna manuellt."
                                    authorized = false
                                })
                                PassportGuideOverlay(captured: captured)
                            }
                        }.frame(height: 400).clipShape(RoundedRectangle(cornerRadius: 24))
                    } else {
                        Image(systemName: "doc.viewfinder").font(.system(size: 64)).padding(40)
                    }
                    Text(message).font(.headline).multilineTextAlignment(.center)
                        .accessibilityIdentifier("passport.instruction")
                    Text("Fotograferas automatiskt när hela sidan och kodraderna kan läsas. Håll passet plant och undvik reflexer.")
                        .font(.subheadline).multilineTextAlignment(.center)
                    Text("Bilden används bara på telefonen för att läsa uppgifterna. Den sparas eller skickas inte.")
                        .font(.footnote).foregroundStyle(.secondary)
                }.padding(20)
            }
            .navigationTitle("Skanna passuppgifter").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Stäng") { dismiss() } } }
            .task {
                let allowed = await AVCaptureDevice.requestAccess(for: .video)
                authorized = allowed
                if !allowed { message = "Tillåt kameraåtkomst i telefonens Inställningar eller fyll i uppgifterna manuellt." }
                else if !DataScannerViewController.isSupported || !DataScannerViewController.isAvailable {
                    message = "Kameraläsningen stöds inte just nu. Du kan fortfarande fylla i uppgifterna manuellt."
                }
            }
            .onChange(of: message) { value in
                if UIAccessibility.isVoiceOverRunning { UIAccessibility.post(notification: .announcement, argument: value) }
            }
        }
    }
}

enum PassportPageFrame {
    static func rect(in size: CGSize) -> CGRect {
        let width = min(size.width * 0.90, size.height * 0.76 * 1.42)
        let height = width / 1.42
        return CGRect(x: (size.width - width) / 2, y: (size.height - height) / 2, width: width, height: height)
    }
}

struct PassportGuideOverlay: View {
    var captured = false
    var body: some View {
        GeometryReader { geometry in
            let frame = PassportPageFrame.rect(in: geometry.size)
            ZStack {
                Path { path in
                    path.addRect(CGRect(origin: .zero, size: geometry.size))
                    path.addRoundedRect(in: frame, cornerSize: CGSize(width: 12, height: 12))
                }.fill(.black.opacity(0.5), style: FillStyle(eoFill: true))
                RoundedRectangle(cornerRadius: 12).stroke(captured ? .green : .white, lineWidth: 3)
                    .frame(width: frame.width, height: frame.height).position(x: frame.midX, y: frame.midY)
                Image(systemName: "person.crop.rectangle").resizable().scaledToFit()
                    .frame(width: frame.width * 0.23, height: frame.height * 0.48)
                    .position(x: frame.minX + frame.width * 0.18, y: frame.minY + frame.height * 0.36)
                    .foregroundStyle(.white.opacity(0.6))
                VStack(spacing: 5) {
                    ForEach(0..<2) { _ in
                        Text(String(repeating: "‹", count: 27)).font(.system(size: 14, weight: .bold, design: .monospaced))
                            .lineLimit(1).minimumScaleFactor(0.5)
                    }
                }.frame(width: frame.width * 0.90, height: frame.height * 0.2)
                    .position(x: frame.midX, y: frame.minY + frame.height * 0.83).foregroundStyle(.white.opacity(0.7))
                Label(captured ? "Bilden är tagen" : "Automatisk fotografering", systemImage: captured ? "checkmark.circle.fill" : "camera.fill")
                    .font(.caption.weight(.semibold)).padding(10).background(.black.opacity(0.7), in: Capsule())
                    .foregroundStyle(.white).position(x: geometry.size.width / 2, y: 30)
            }
        }.allowsHitTesting(false).accessibilityHidden(true).accessibilityIdentifier("passport.guide")
    }
}

private struct MRZCamera: UIViewControllerRepresentable {
    let pageFrame: CGRect
    let onRead: (PassportMRZ) -> Void
    let onGuidance: (String, Bool) -> Void
    let onFailure: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(onRead: onRead, onGuidance: onGuidance, onFailure: onFailure) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.text(languages: ["en-US"])],
            qualityLevel: .accurate, recognizesMultipleItems: true, isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: false, isGuidanceEnabled: false, isHighlightingEnabled: false)
        scanner.delegate = context.coordinator
        scanner.regionOfInterest = pageFrame
        do { try scanner.startScanning(); context.coordinator.start(scanner) }
        catch { DispatchQueue.main.async { onFailure() } }
        return scanner
    }
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) { controller.regionOfInterest = pageFrame }
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        coordinator.finished = true; coordinator.task?.cancel(); coordinator.candidate = nil
        controller.stopScanning(); controller.delegate = nil
    }
    @MainActor final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        var finished = false
        var candidate: PassportMRZ?
        var task: Task<Void, Never>?
        let onRead: (PassportMRZ) -> Void
        let onGuidance: (String, Bool) -> Void
        let onFailure: () -> Void
        init(onRead: @escaping (PassportMRZ) -> Void, onGuidance: @escaping (String, Bool) -> Void, onFailure: @escaping () -> Void) {
            self.onRead = onRead; self.onGuidance = onGuidance; self.onFailure = onFailure
        }
        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) { read(allItems) }
        func dataScanner(_ scanner: DataScannerViewController, didUpdate updatedItems: [RecognizedItem], allItems: [RecognizedItem]) { read(allItems) }
        func dataScanner(_ scanner: DataScannerViewController, didRemove removedItems: [RecognizedItem], allItems: [RecognizedItem]) { read(allItems) }
        func dataScanner(_ scanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            guard !finished else { return }; finished = true; task?.cancel(); candidate = nil; onFailure()
        }
        private func read(_ items: [RecognizedItem]) {
            guard !finished else { return }
            candidate = PassportMRZ.parse(items.compactMap { item -> String? in
                if case .text(let value) = item { return value.transcript }; return nil
            }.joined(separator: "\n"))
        }
        func start(_ scanner: DataScannerViewController) {
            task = Task { [weak self, weak scanner] in
                while !Task.isCancelled {
                    do { try await Task.sleep(nanoseconds: 700_000_000) } catch { return }
                    guard let self, let scanner, !self.finished else { return }
                    guard let expected = self.candidate else { continue }
                    do {
                        let photo = try await scanner.capturePhoto()
                        guard !Task.isCancelled, !self.finished else { return }
                        // Normalize UIImage orientation before running Vision off the main thread.
                        let scale = min(1, 1800 / max(photo.size.width, photo.size.height))
                        let size = CGSize(width: photo.size.width * scale, height: photo.size.height * scale)
                        let format = UIGraphicsImageRendererFormat(); format.scale = 1
                        guard let image = UIGraphicsImageRenderer(size: size, format: format).image(actions: { _ in
                            photo.draw(in: CGRect(origin: .zero, size: size))
                        }).cgImage else { continue }
                        let assessment = await Task.detached(priority: .userInitiated) { PassportPhotoAssessment.evaluate(image, expected: expected) }.value
                        guard !Task.isCancelled, !self.finished else { return }
                        if let hint = assessment {
                            self.onGuidance(hint, false)
                        } else {
                            self.finished = true; self.candidate = nil; scanner.stopScanning()
                            self.onGuidance("Bilden är tagen", true)
                            UINotificationFeedbackGenerator().notificationOccurred(.success)
                            try await Task.sleep(nanoseconds: 300_000_000)
                            guard !Task.isCancelled else { return }
                            self.onRead(expected); return
                        }
                    } catch {
                        guard !Task.isCancelled, !self.finished else { return }
                        self.finished = true; self.onFailure(); return
                    }
                }
            }
        }
    }
}

/// Composition/readability only. The photo stays in memory and never replaces chip authenticity checks.
enum PassportPhotoAssessment {
    static func evaluate(_ image: CGImage, expected: PassportMRZ) -> String? {
        do {
            let rectangles = VNDetectRectanglesRequest()
            rectangles.maximumObservations = 4; rectangles.minimumConfidence = 0.7
            rectangles.minimumAspectRatio = 0.5; rectangles.maximumAspectRatio = 1
            rectangles.minimumSize = 0.25; rectangles.quadratureTolerance = 25
            try VNImageRequestHandler(cgImage: image, options: [:]).perform([rectangles])
            let pages = (rectangles.results ?? []).filter { page in
                let b = page.boundingBox
                let aspect = b.width * CGFloat(image.width) / (b.height * CGFloat(image.height))
                return b.minX > 0.015 && b.maxX < 0.985 && b.minY > 0.015 && b.maxY < 0.985
                    && abs(b.midX - 0.5) < 0.22 && abs(b.midY - 0.5) < 0.22
                    && b.width > 0.45 && (1.1...1.85).contains(aspect)
            }
            guard let page = pages.max(by: { $0.boundingBox.width * $0.boundingBox.height < $1.boundingBox.width * $1.boundingBox.height }) else {
                return "Visa hela porträttsidan, med lite luft runt kanterna"
            }
            let ci = CIImage(cgImage: image)
            func vector(_ point: CGPoint) -> CIVector { CIVector(x: point.x * ci.extent.width, y: point.y * ci.extent.height) }
            let corrected = ci.applyingFilter("CIPerspectiveCorrection", parameters: [
                "inputTopLeft": vector(page.topLeft), "inputTopRight": vector(page.topRight),
                "inputBottomLeft": vector(page.bottomLeft), "inputBottomRight": vector(page.bottomRight)])
            guard let crop = CIContext().createCGImage(corrected, from: corrected.extent) else { return "Håll telefonen stilla en kort stund" }
            let text = VNRecognizeTextRequest()
            text.recognitionLevel = .accurate; text.usesLanguageCorrection = false; text.recognitionLanguages = ["en-US"]
            try VNImageRequestHandler(cgImage: crop, options: [:]).perform([text])
            let lines = (text.results ?? []).compactMap { observation -> String? in
                guard observation.boundingBox.midY < 0.35, let value = observation.topCandidates(1).first, value.confidence >= 0.75 else { return nil }
                return value.string
            }.joined(separator: "\n")
            guard PassportMRZ.parse(lines) == expected else { return "Håll stilla och undvik reflexer över kodraderna" }
            return nil
        } catch { return "Bilden kunde inte läsas. Håll passet plant och försök igen" }
    }
}
