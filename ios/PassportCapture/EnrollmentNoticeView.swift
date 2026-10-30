import SwiftUI

struct EnrollmentNoticeView: View {
    let notice: EnrollmentText
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Innan du registrerar dig").font(.title2.bold())
            Text("Ansvarig: \(notice.controller)")
            Text("Kontakt: \(notice.contact)").textSelection(.enabled)
            Text("Version: \(notice.version)").font(.caption)
            DisclosureGroup("Användarvillkor") { Text(notice.terms).textSelection(.enabled).padding(.top, 8) }
            DisclosureGroup("Så behandlas dina personuppgifter") { Text(notice.privacy).textSelection(.enabled).padding(.top, 8) }
            Text("Biometrisk identitetskontroll").font(.headline)
            Text(notice.biometrics).textSelection(.enabled)
            Text("Återkalla samtycket").font(.headline)
            Text(notice.withdrawal).textSelection(.enabled)
        }.font(.subheadline)
    }
}

struct EnrollmentReceiptsView: View {
    @EnvironmentObject var model: WalletModel
    @State private var receipts: [EnrollmentReceipt] = []
    @State private var issue: String?
    @State private var selected: EnrollmentReceipt?

    private func reload() {
        do {
            guard model.unlocked, let credential = model.credential else { receipts = []; return }
            receipts = try EnrollmentReceiptStore().read(for: credential.id).reversed()
        } catch { issue = "Kvittona kunde inte läsas från telefonen." }
    }

    var body: some View {
        List {
            Section {
                Text("Samtycket avser registreringens biometriska kontroll. När en återkallelse bekräftats stoppar den fortsatt registrering med samma kvitto. Redan utförd behandling kan inte göras ogjord. Ditt ID spärras separat under Inställningar.")
                Text("För radering, andra rättigheter eller förlorad telefon använder du kontakten i informationen nedan. Återkallelse kräver att registreringsservern är tillgänglig.")
            }
            if receipts.isEmpty {
                Text("Inga versionsbundna kvitton finns för den här nyckeln på telefonen. Äldre registreringar behöver kontrolleras separat.")
            }
            ForEach(receipts) { receipt in
                Section {
                    if let text = try? receipt.notice.text() { EnrollmentNoticeView(notice: text) }
                    Text(receipt.state == .withdrawn ? "Återkallelsen är bekräftad" : receipt.state == .recorded ? "Valet är registrerat" : "Serverns mottagande är inte bekräftat")
                        .font(.headline)
                    Text("Kvitto: \(receipt.id)").font(.caption.monospaced()).textSelection(.enabled)
                    if let data = try? JSONEncoder().encode(receipt), let copy = String(data: data, encoding: .utf8) {
                        ShareLink("Spara en kopia av kvittot", item: copy)
                    }
                    if receipt.state != .withdrawn {
                        Button("Återkalla biometriskt samtycke", role: .destructive) { selected = receipt }
                            .disabled(model.busy)
                    }
                }
            }
            if let message = model.statusMessage { Text(message) }
            if let error = model.error { Text(error) }
            if let issue { Text(issue) }
        }.navigationTitle("Dina samtycken")
            .task { reload() }
            .onChange(of: model.busy) { busy in if !busy { reload() } }
            .confirmationDialog("Återkalla detta samtycke?", isPresented: Binding(
                get: { selected != nil }, set: { if !$0 { selected = nil } }), titleVisibility: .visible) {
                if let selected { Button("Återkalla samtycket", role: .destructive) { model.withdrawEnrollmentConsent(selected.id) } }
            } message: { Text("Pågående registrering med kvittot stoppas när servern bekräftar återkallelsen. Det raderar inte automatiskt tidigare uppgifter eller spärrar ett befintligt ID.") }
    }
}
