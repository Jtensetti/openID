import SwiftUI

@main struct PassportCaptureApp: App {
    @StateObject private var flow = VerificationFlow()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                Form {
                    Section("Anslut till din verifierare") {
                        TextField("https://server:8765", text: $flow.server).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        SecureField("Kopplingskod", text: $flow.pairing)
                    }.disabled(flow.busy)
                    Section("Läs ditt pass") {
                        TextField("Passnummer", text: $flow.documentNumber).textInputAutocapitalization(.characters).autocorrectionDisabled()
                        TextField("Födelsedatum · ÅÅMMDD", text: $flow.birth).keyboardType(.numberPad)
                        TextField("Giltigt till · ÅÅMMDD", text: $flow.expiry).keyboardType(.numberPad)
                        Text("Uppgifterna öppnar chipets skyddade kanal och sparas inte av appen.").font(.footnote)
                    }.disabled(flow.busy)
                    Section {
                        Text("När du startar läses passets chip. Därefter tas tre kamerabilder som tillsammans med chipdata skickas till din verifierare för kontroll. Ingen bild hämtas från bildbiblioteket.")
                        Button("Starta pass- och personkontroll") { flow.start() }.disabled(flow.busy)
                        if flow.busy { Button("Avbryt", role: .cancel) { flow.cancel() } }
                    }
                    if flow.cameraVisible { CameraPreview(session: flow.camera.session).frame(height: 320).clipShape(RoundedRectangle(cornerRadius: 16)) }
                    Section("Status") { Text(flow.status).accessibilityAddTraits(.updatesFrequently) }
                }.navigationTitle("openID · pass & person")
            }.onChange(of: phase) { value in if value == .background { flow.cancel() } }
        }
    }
}
