import Foundation
import CoreFoundation
import CoreNFC

struct ChipRelayCommand {
    let sequence: Int
    let bytes: Data

    init(_ response: [String: Any], expectedSequence: Int) throws {
        guard response["type"] as? String == "command",
              let sequence = response["sequence"] as? NSNumber,
              CFGetTypeID(sequence) != CFBooleanGetTypeID(),
              sequence.doubleValue == Double(expectedSequence), (0..<128).contains(expectedSequence),
              let encoded = response["command"] as? String, encoded.count <= 5464,
              let bytes = Data(base64Encoded: encoded), (4...261).contains(bytes.count),
              [0x00, 0x0C, 0x10, 0x1C].contains(bytes[0]),
              [0xA4, 0xB0, 0x22, 0x86, 0xC0].contains(bytes[1]) else { throw WalletError.rejected }
        if bytes.count > 5 {
            let size = Int(bytes[4])
            guard size > 0, bytes.count == 5 + size || bytes.count == 6 + size else { throw WalletError.rejected }
        }
        self.sequence = expectedSequence
        self.bytes = bytes
    }
}

@MainActor final class PassportChipRelay: NSObject, NFCTagReaderSessionDelegate {
    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<[String: Any], Error>?
    private var exchange: Task<Void, Never>?
    private var api: WalletAPI?
    private var initial: [String: Any] = [:]
    private var id = ""
    private var token = ""

    func authenticate(api: WalletAPI, initial: [String: Any]) async throws -> [String: Any] {
        guard continuation == nil, NFCTagReaderSession.readingAvailable,
              let id = initial["id"] as? String, let token = initial["chipToken"] as? String else { throw WalletError.rejected }
        _ = try ChipRelayCommand(initial, expectedSequence: 0)
        self.api = api; self.initial = initial; self.id = id; self.token = token
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                self.session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
                guard let session else { finish(.failure(WalletError.rejected)); return }
                session.alertMessage = "Håll telefonen mot passet igen för säkerhetskontrollen."
                session.begin()
            }
        }, onCancel: { Task { @MainActor in self.cancel() } })
    }

    nonisolated func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    nonisolated func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Task { @MainActor in
            guard self.session === session else { return }
            self.finish(.failure(WalletError.rejected))
        }
    }

    nonisolated func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor in
            guard self.session === session, self.exchange == nil else { return }
            guard tags.count == 1, case let .iso7816(chip) = tags[0], let api = self.api else {
                self.finish(.failure(WalletError.rejected)); return
            }
            self.exchange = Task {
                do {
                    try await session.connect(to: tags[0])
                    var message = self.initial
                    var sequence = 0
                    while true {
                        try Task.checkCancellation()
                        let command = try ChipRelayCommand(message, expectedSequence: sequence)
                        guard let apdu = NFCISO7816APDU(data: command.bytes) else { throw WalletError.rejected }
                        let (data, sw1, sw2) = try await chip.sendCommand(apdu: apdu)
                        try Task.checkCancellation()
                        guard self.session === session else { throw CancellationError() }
                        guard data.count <= 4094 else { throw WalletError.rejected }
                        var response = data; response.append(sw1); response.append(sw2)
                        message = try await api.postObject("/native/chip/step", body: ["id": self.id,
                            "chipToken": self.token, "sequence": sequence, "response": response.base64EncodedString()])
                        try Task.checkCancellation()
                        guard self.session === session else { throw CancellationError() }
                        if message["type"] as? String == "verified" {
                            guard message["id"] as? String == self.id, let nonce = message["nonce"] as? String,
                                  nonce.count == 43, message["frameCount"] as? Int == 3 else { throw WalletError.rejected }
                            self.finish(.success(message)); return
                        }
                        sequence += 1
                    }
                } catch {
                    guard self.session === session else { return }
                    self.finish(.failure(error))
                }
            }
        }
    }

    func cancel() { finish(.failure(CancellationError())) }

    private func finish(_ result: Result<[String: Any], Error>) {
        guard let continuation else { return }
        self.continuation = nil
        exchange?.cancel(); exchange = nil
        let activeSession = session; session = nil
        activeSession?.invalidate()
        api = nil; initial = [:]; id = ""; token = ""
        continuation.resume(with: result)
    }
}
