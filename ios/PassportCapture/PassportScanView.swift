import SwiftUI
import VisionKit
import AVFoundation

struct PassportScanView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var authorized = false
    @State private var message = "Rikta kameran mot de två kodraderna längst ned på passets fotosida. Håll hela bredden synlig och undvik reflexer."
    let onRead: (PassportMRZ) -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Text(message).padding(.horizontal).accessibilityAddTraits(.updatesFrequently)
                if authorized && DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    MRZCamera(onRead: { value in onRead(value); dismiss() }, onFailure: {
                        message = "Kameraläsningen är inte tillgänglig. Stäng och fyll i uppgifterna manuellt."
                        authorized = false
                    })
                } else {
                    Image(systemName: "doc.viewfinder").font(.system(size: 64)).padding()
                    Spacer()
                }
                Text("Texten läses på telefonen. Ingen bild sparas eller skickas.").font(.footnote).foregroundStyle(.secondary).padding()
            }
            .navigationTitle("Skanna passuppgifter")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Stäng") { dismiss() } } }
            .task {
                let allowed = await AVCaptureDevice.requestAccess(for: .video)
                authorized = allowed
                if !allowed { message = "Tillåt kameraåtkomst i telefonens Inställningar eller fyll i uppgifterna manuellt." }
                else if !DataScannerViewController.isSupported || !DataScannerViewController.isAvailable {
                    message = "Kameraläsningen stöds inte just nu. Du kan fortfarande fylla i uppgifterna manuellt."
                }
            }
        }
    }
}

private struct MRZCamera: UIViewControllerRepresentable {
    let onRead: (PassportMRZ) -> Void
    let onFailure: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(onRead: onRead, onFailure: onFailure) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.text(languages: ["en-US"])],
            qualityLevel: .accurate, recognizesMultipleItems: true, isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true, isGuidanceEnabled: true, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        do { try scanner.startScanning() } catch { DispatchQueue.main.async { onFailure() } }
        return scanner
    }
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        coordinator.finished = true; controller.stopScanning(); controller.delegate = nil
    }
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        var finished = false
        let onRead: (PassportMRZ) -> Void
        let onFailure: () -> Void
        init(onRead: @escaping (PassportMRZ) -> Void, onFailure: @escaping () -> Void) {
            self.onRead = onRead; self.onFailure = onFailure
        }
        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) { read(scanner, allItems) }
        func dataScanner(_ scanner: DataScannerViewController, didUpdate updatedItems: [RecognizedItem], allItems: [RecognizedItem]) { read(scanner, allItems) }
        func dataScanner(_ scanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            guard !finished else { return }; finished = true; onFailure()
        }
        private func read(_ scanner: DataScannerViewController, _ items: [RecognizedItem]) {
            guard !finished else { return }
            let text = items.compactMap { item -> String? in
                if case .text(let value) = item { return value.transcript }; return nil
            }.joined(separator: "\n")
            guard let value = PassportMRZ.parse(text) else { return }
            finished = true; scanner.stopScanning()
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            onRead(value)
        }
    }
}
