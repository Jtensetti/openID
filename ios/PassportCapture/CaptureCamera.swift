import AVFoundation
import CoreImage
import ImageIO
import SwiftUI
import Vision

final class CaptureCamera: NSObject, ObservableObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    let session = AVCaptureSession()
    @Published private(set) var guidance = CaptureGuidance()
    private let queue = DispatchQueue(label: "se.openid.camera")
    private let context = CIContext()
    private let lock = NSLock()
    private var activeRun: CaptureRun?
    private var queueRun: CaptureRun?
    private var continuation: CheckedContinuation<[Data], Error>?
    private var frames = [Data]()
    private var guide = CaptureGuide()
    private var lastAnalysis = -Double.infinity
    private var videoOutput: AVCaptureVideoDataOutput?
    private var observers = [NSObjectProtocol]()

    func capture() async throws -> [Data] {
        let run = CaptureRun()
        guard lock.withLock({
            guard activeRun == nil else { return false }
            activeRun = run; return true
        }) else { throw CaptureError.unavailable }
        defer { lock.withLock { if activeRun === run { activeRun = nil } } }
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            guard await AVCaptureDevice.requestAccess(for: .video) else { throw CaptureError.denied }
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    guard !run.cancelled else { continuation.resume(throwing: CancellationError()); return }
                    self.queueRun = run; self.continuation = continuation
                    self.guide = CaptureGuide(); self.frames = []; self.lastAnalysis = -Double.infinity
                    self.publish(run)
                    do {
                        try self.configure()
                        for name in [AVCaptureSession.wasInterruptedNotification, AVCaptureSession.runtimeErrorNotification] {
                            self.observers.append(NotificationCenter.default.addObserver(forName: name, object: self.session, queue: nil) { [weak self] _ in
                                self?.queue.async { self?.finish(.failure(CaptureError.unavailable), run: run) }
                            })
                        }
                        self.session.startRunning()
                        guard !run.cancelled else { self.finish(.failure(CancellationError()), run: run); return }
                        self.queue.asyncAfter(deadline: .now() + 45) { self.finish(.failure(CaptureError.timeout), run: run) }
                    } catch { self.finish(.failure(CaptureError.unavailable), run: run) }
                }
            }
        }, onCancel: { self.cancel(run) })
    }

    private func configure() throws {
        session.beginConfiguration()
        defer { session.commitConfiguration() }
        session.sessionPreset = .hd1280x720
        for input in session.inputs { session.removeInput(input) }
        for output in session.outputs { session.removeOutput(output) }
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .front) else { throw CaptureError.unavailable }
        let input = try AVCaptureDeviceInput(device: device)
        let output = AVCaptureVideoDataOutput()
        output.alwaysDiscardsLateVideoFrames = true
        output.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        guard session.canAddInput(input), session.canAddOutput(output) else { throw CaptureError.unavailable }
        session.addInput(input); session.addOutput(output); videoOutput = output
        output.setSampleBufferDelegate(self, queue: queue)
        guard let connection = output.connection(with: .video), connection.isVideoOrientationSupported else { throw CaptureError.unavailable }
        connection.videoOrientation = .portrait
        connection.automaticallyAdjustsVideoMirroring = false
        if connection.isVideoMirroringSupported { connection.isVideoMirrored = false }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard let run = queueRun, !run.cancelled, output === videoOutput,
              let buffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let time = CMTimeGetSeconds(CMSampleBufferGetPresentationTimeStamp(sampleBuffer))
        guard time.isFinite, time - lastAnalysis >= 0.09 else { return }
        lastAnalysis = time
        do {
            let handler = VNImageRequestHandler(cvPixelBuffer: buffer, orientation: .up, options: [:])
            let detection = VNDetectFaceRectanglesRequest()
            detection.revision = VNDetectFaceRectanglesRequestRevision3
            try handler.perform([detection])
            let faces = detection.results ?? []
            var quality: Double?
            if faces.count == 1 {
                let request = VNDetectFaceCaptureQualityRequest()
                request.revision = VNDetectFaceCaptureQualityRequestRevision2
                request.inputFaceObservations = faces
                try handler.perform([request])
                if request.results?.count == 1 { quality = request.results?.first?.faceCaptureQuality?.doubleValue }
            }
            let observations = faces.map { face in
                CaptureFace(bounds: face.boundingBox, yaw: face.yaw?.doubleValue, pitch: face.pitch?.doubleValue,
                            roll: face.roll?.doubleValue, quality: quality)
            }
            let captureFrame = guide.observe(observations, at: time)
            guard !run.cancelled else { return }
            publish(run)
            guard captureFrame else { return }
            let image = CIImage(cvPixelBuffer: buffer)
            guard let jpeg = context.jpegRepresentation(of: image, colorSpace: CGColorSpaceCreateDeviceRGB(),
                    options: [CIImageRepresentationOption(rawValue: kCGImageDestinationLossyCompressionQuality as String): 0.85]),
                  jpeg.count <= 2_000_000 else { throw CaptureError.unavailable }
            frames.append(jpeg)
            if frames.count == 3 { finish(.success(frames), run: run) }
        } catch { finish(.failure(CaptureError.unavailable), run: run) }
    }

    func stop() { if let run = lock.withLock({ activeRun }) { cancel(run) } }

    private func cancel(_ run: CaptureRun) {
        run.cancel()
        queue.async { self.finish(.failure(CancellationError()), run: run) }
    }
    private func publish(_ run: CaptureRun) {
        let value = guide.guidance
        DispatchQueue.main.async {
            guard self.lock.withLock({ self.activeRun === run }), !run.cancelled else { return }
            self.guidance = value
        }
    }
    private func finish(_ result: Result<[Data], Error>, run: CaptureRun) {
        guard queueRun === run else { return }
        observers.forEach { NotificationCenter.default.removeObserver($0) }; observers.removeAll()
        videoOutput?.setSampleBufferDelegate(nil, queue: nil); videoOutput = nil
        session.stopRunning(); frames.removeAll(); queueRun = nil
        let pending = continuation; continuation = nil
        pending?.resume(with: run.cancelled ? .failure(CancellationError()) : result)
    }
    enum CaptureError: Error { case denied, unavailable, timeout }
}

private final class CaptureRun {
    private let lock = NSLock()
    private var stopped = false
    var cancelled: Bool { lock.withLock { stopped } }
    func cancel() { lock.withLock { stopped = true } }
}

struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession
    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView(); view.preview.session = session; view.preview.videoGravity = .resizeAspect
        return view
    }
    func updateUIView(_ uiView: PreviewView, context: Context) {
        if let connection = uiView.preview.connection {
            if connection.isVideoOrientationSupported { connection.videoOrientation = .portrait }
            connection.automaticallyAdjustsVideoMirroring = false
            if connection.isVideoMirroringSupported { connection.isVideoMirrored = true }
        }
    }
}
final class PreviewView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    var preview: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
}
