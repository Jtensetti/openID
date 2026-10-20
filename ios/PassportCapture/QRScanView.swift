import SwiftUI
import AVFoundation

struct QRScanView: View {
    let selected: (URL) -> Void
    @Environment(\.dismiss) private var dismiss
    @StateObject private var reader = RequestQRReader()
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Text("Skanna koden hos tjänsten där du startade inloggningen.").font(.headline).multilineTextAlignment(.center)
                CameraPreview(session: reader.session).frame(height: 350).clipShape(RoundedRectangle(cornerRadius: 24))
                Text(reader.message).font(.subheadline).foregroundStyle(.secondary)
            }.padding(24).navigationTitle("Skanna begäran").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Avbryt") { dismiss() } } }
        }.task { await reader.start { selected($0) } }.onDisappear { reader.stop() }
    }
}
final class RequestQRReader: NSObject, ObservableObject, AVCaptureMetadataOutputObjectsDelegate {
    let session = AVCaptureSession()
    @Published var message = "Rikta kameran mot QR-koden."
    private let queue = DispatchQueue(label: "se.openid.qr")
    private let lock = NSLock()
    private var stopped = false
    private var selected: ((URL) -> Void)?
    func start(selected: @escaping (URL) -> Void) async {
        self.selected = selected
        guard await AVCaptureDevice.requestAccess(for: .video), !Task.isCancelled else {
            await MainActor.run { self.message = "Kamerabehörighet behövs. Du kan också öppna en begärandelänk." }; return
        }
        queue.async {
            guard !self.lock.withLock({ self.stopped }) else { return }
            self.session.beginConfiguration()
            do {
                guard let camera = AVCaptureDevice.default(for: .video) else { throw WalletError.unavailable }
                let input = try AVCaptureDeviceInput(device: camera)
                let output = AVCaptureMetadataOutput()
                guard self.session.canAddInput(input), self.session.canAddOutput(output) else { throw WalletError.unavailable }
                self.session.addInput(input); self.session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]
                self.session.commitConfiguration(); self.session.startRunning()
            } catch {
                self.session.commitConfiguration()
                DispatchQueue.main.async { self.message = "Kameran kunde inte öppnas." }
            }
        }
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !lock.withLock({ stopped }), let text = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        guard text.count < 256, let url = URL(string: text), RequestLink.identifier(url) != nil else {
            message = "Koden är inte en giltig openID-begäran."; return
        }
        stop(); selected?(url)
    }
    func stop() { lock.withLock { stopped = true }; queue.async { self.session.stopRunning() } }
}
