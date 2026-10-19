import AVFoundation
import CoreImage
import ImageIO
import SwiftUI

final class CaptureCamera: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "se.openid.camera")
    private let context = CIContext()
    private var continuation: CheckedContinuation<[Data], Error>?
    private var frames = [Data]()
    private var lastTime = 0.0
    private var started = 0.0
    private let lock = NSLock()
    private var cancelled = false

    func capture() async throws -> [Data] {
        lock.withLock { cancelled = false }
        try Task.checkCancellation()
        guard await AVCaptureDevice.requestAccess(for: .video) else { throw CaptureError.denied }
        try Task.checkCancellation()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    guard !self.lock.withLock({ self.cancelled }), !self.session.isRunning else { continuation.resume(throwing: CaptureError.denied); return }
                    self.continuation = continuation
                    do {
                        self.session.beginConfiguration()
                        self.session.sessionPreset = .hd1280x720
                        for input in self.session.inputs { self.session.removeInput(input) }
                        for output in self.session.outputs { self.session.removeOutput(output) }
                        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .front) else { throw CaptureError.denied }
                        let input = try AVCaptureDeviceInput(device: device)
                        let output = AVCaptureVideoDataOutput()
                        output.alwaysDiscardsLateVideoFrames = true
                        output.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
                        guard self.session.canAddInput(input), self.session.canAddOutput(output) else { throw CaptureError.denied }
                        self.session.addInput(input); self.session.addOutput(output)
                        output.setSampleBufferDelegate(self, queue: self.queue)
                        if let connection = output.connection(with: .video) {
                            connection.videoOrientation = .portrait
                            if connection.isVideoMirroringSupported { connection.isVideoMirrored = false }
                        }
                        self.session.commitConfiguration()
                        self.frames = []; self.lastTime = 0; self.started = CACurrentMediaTime()
                        self.session.startRunning()
                        let captureStarted = self.started
                        self.queue.asyncAfter(deadline: .now() + 12) {
                            if self.started == captureStarted && self.continuation != nil { self.finish(.failure(CaptureError.denied)) }
                        }
                    } catch {
                        self.session.commitConfiguration(); self.finish(.failure(CaptureError.denied))
                    }
                }
            }
        }, onCancel: { self.stop() })
    }
    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard continuation != nil else { return }
        let now = CACurrentMediaTime()
        guard now - started > 1.5, now - lastTime > 0.8, let buffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let image = CIImage(cvPixelBuffer: buffer)
        guard let jpeg = context.jpegRepresentation(of: image, colorSpace: CGColorSpaceCreateDeviceRGB(), options: [CIImageRepresentationOption(rawValue: kCGImageDestinationLossyCompressionQuality as String): 0.85]), jpeg.count <= 2_000_000 else {
            finish(.failure(CaptureError.denied)); return
        }
        frames.append(jpeg); lastTime = now
        if frames.count == 3 { finish(.success(frames)) }
    }
    func stop() { lock.withLock { cancelled = true }; queue.async { self.finish(.failure(CancellationError())) } }
    private func finish(_ result: Result<[Data], Error>) {
        session.stopRunning(); frames.removeAll()
        let pending = continuation; continuation = nil; pending?.resume(with: result)
    }
    enum CaptureError: Error { case denied }
}

struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession
    func makeUIView(context: Context) -> PreviewView { let view = PreviewView(); view.preview.session = session; view.preview.videoGravity = .resizeAspectFill; return view }
    func updateUIView(_ uiView: PreviewView, context: Context) {}
}
final class PreviewView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    var preview: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
}
