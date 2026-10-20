import SwiftUI

// All screens are native SwiftUI; no remote UI, analytics, external fonts or web content.
enum Palette {
    static let ink = Color(red: 0.06, green: 0.16, blue: 0.19)
    static let mint = Color(red: 0.73, green: 0.94, blue: 0.80)
    static let paper = Color(red: 0.96, green: 0.96, blue: 0.93)
    static let muted = Color(red: 0.34, green: 0.41, blue: 0.42)
}

struct WalletRootView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        TabView(selection: $model.selectedTab) {
            NavigationStack { HomeView() }.tabItem { Label("Mitt ID", systemImage: "person.crop.rectangle") }.tag(0)
            NavigationStack { RequestsView() }.tabItem { Label("Legitimera", systemImage: "qrcode.viewfinder") }.tag(1)
            NavigationStack { ActivityView() }.tabItem { Label("Aktivitet", systemImage: "clock") }.tag(2)
            NavigationStack { SettingsView() }.tabItem { Label("Inställningar", systemImage: "slider.horizontal.3") }.tag(3)
        }
        .tint(Palette.ink)
        .sheet(isPresented: $model.registrationPresented) {
            EnrollmentView(flow: model.verification).environmentObject(model)
        }
        .sheet(isPresented: $model.settingsPresented) { NavigationStack { ConnectionView() }.environmentObject(model) }
        .sheet(item: $model.focusedRequest) { request in
            NavigationStack { ApprovalView(request: request) }.environmentObject(model)
        }
        .alert("Kunde inte slutföra", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK", role: .cancel) { model.error = nil }
        } message: { Text(model.error ?? "") }
    }
}

private struct Brand: View {
    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: "circle.hexagongrid.fill").font(.title2).foregroundStyle(Palette.ink)
            Text("openID").font(.system(size: 24, weight: .bold, design: .rounded)).foregroundStyle(Palette.ink)
            Spacer()
            Text("PRIVAT PILOT").font(.system(size: 9, weight: .bold, design: .monospaced))
                .tracking(1.2).padding(.horizontal, 10).padding(.vertical, 7)
                .background(Palette.ink.opacity(0.06), in: Capsule())
        }
    }
}
struct PrimaryButton: View {
    let title: String
    var symbol = "arrow.right"
    var action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack { Text(title).font(.headline); Spacer(); Image(systemName: symbol) }
                .padding(19).foregroundStyle(Palette.mint).background(Palette.ink, in: RoundedRectangle(cornerRadius: 18))
        }.buttonStyle(.plain)
    }
}
struct HomeView: View {
    @EnvironmentObject var model: WalletModel
    @State private var guide = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Brand()
                VStack(alignment: .leading, spacing: 8) {
                    Text("Din identitet.\nDitt godkännande.")
                        .font(.system(size: 36, weight: .semibold, design: .rounded)).tracking(-1.1)
                        .fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("home.heading")
                    Text("Ett tydligt ja. Bara från dig.").font(.subheadline).foregroundStyle(Palette.muted)
                }
                IdentityCard()
                VStack(spacing: 12) {
                    if !model.unlocked {
                        PrimaryButton(title: "Öppna openID", symbol: "faceid") { model.unlock() }
                            .accessibilityIdentifier("home.unlock").disabled(model.busy)
                    } else if model.configuration == nil {
                        PrimaryButton(title: "Kom igång") { model.settingsPresented = true }
                    } else if model.credential == nil {
                        PrimaryButton(title: "Registrera med ditt pass", symbol: "person.crop.rectangle.badge.plus") { model.beginRegistration() }
                    } else {
                        PrimaryButton(title: "Uppdatera mitt ID", symbol: "arrow.clockwise") { model.refresh() }.disabled(model.busy)
                        if model.snapshot == nil {
                            Button("Fortsätt passregistrering") { model.beginRegistration() }.font(.subheadline)
                        }
                    }
                    if model.busy { ProgressView("Kontrollerar…").accessibilityIdentifier("home.progress") }
                }
                HStack(alignment: .top, spacing: 13) {
                    Image(systemName: "lock.shield").font(.title2).padding(.top, 2)
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Nyckeln stannar hos dig").font(.subheadline.bold())
                        Text("Din enhetsnyckel skyddas i telefonen. Du ser alltid vem som ber dig legitimera dig.")
                            .font(.footnote).foregroundStyle(Palette.muted).fixedSize(horizontal: false, vertical: true)
                    }
                }.padding(18).background(.white.opacity(0.75), in: RoundedRectangle(cornerRadius: 18))
                Button { guide = true } label: {
                    HStack { Text("Så fungerar openID").font(.subheadline.weight(.medium)); Spacer(); Image(systemName: "arrow.up.right") }
                }.accessibilityIdentifier("home.guide")
                Text("Den här versionen används i en privat pilot. Ingen godkänd e-legitimation har utfärdats.")
                    .font(.caption).foregroundStyle(Palette.muted)
            }.padding(24)
        }.background(Palette.paper).foregroundStyle(Palette.ink)
            .toolbar(.hidden, for: .navigationBar)
            .sheet(isPresented: $guide) { NavigationStack { GuideView() } }
    }
}
struct IdentityCard: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack {
                Text("openID").font(.system(size: 22, weight: .semibold, design: .rounded))
                Spacer()
                Image(systemName: "wave.3.right").font(.title2).rotationEffect(.degrees(90))
            }
            HStack(alignment: .center, spacing: 16) {
                Image(systemName: "person.crop.rectangle").font(.system(size: 38, weight: .ultraLight))
                    .frame(width: 68, height: 68).background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 18))
                VStack(alignment: .leading, spacing: 8) {
                    Text(model.unlocked && model.credential != nil ? "Mitt ID" : "Ditt nästa ID").font(.title2.weight(.medium))
                    HStack(spacing: 6) {
                        Circle().fill(Palette.mint).frame(width: 6, height: 6)
                        Text(model.snapshot?.state.title ?? (model.unlocked && model.credential != nil ? "Status behöver hämtas" : "Börja med ditt pass"))
                            .font(.caption).fixedSize(horizontal: false, vertical: true)
                    }.foregroundStyle(Palette.mint)
                }
            }
            HStack {
                Text("ENHETSBUNDET").font(.system(size: 9, weight: .medium, design: .monospaced)).tracking(2)
                Spacer()
                Text(model.snapshot.map { "ID · " + String($0.credentialId.suffix(6)).uppercased() } ?? "••••  ••••")
                    .font(.system(size: 11, design: .monospaced))
            }.foregroundStyle(.white.opacity(0.55))
        }
        .padding(24).foregroundStyle(.white)
        .background(LinearGradient(colors: [Palette.ink, Color(red: 0.10, green: 0.26, blue: 0.27)], startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: 25))
        .accessibilityElement(children: .combine).accessibilityIdentifier("identity.card")
    }
}
struct EmptyPanel: View {
    let symbol: String
    let title: String
    let message: String
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: symbol).font(.system(size: 44, weight: .light)).foregroundStyle(Palette.ink)
                .frame(width: 92, height: 92).background(Palette.mint.opacity(0.5), in: Circle())
            Text(title).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
            Text(message).font(.subheadline).foregroundStyle(Palette.muted).multilineTextAlignment(.center)
        }.padding(32).frame(maxWidth: .infinity)
    }
}
struct RequestsView: View {
    @EnvironmentObject var model: WalletModel
    @State private var scanner = false
    @State private var link = ""
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                if !model.unlocked {
                    EmptyPanel(symbol: "lock", title: "Lås upp för att legitimera dig", message: "Dina begäranden visas efter att du har öppnat openID.")
                    PrimaryButton(title: "Öppna openID", symbol: "faceid") { model.unlock() }
                } else if model.snapshot?.state != .active {
                    EmptyPanel(symbol: "person.crop.rectangle", title: "Ditt ID behöver vara aktivt", message: "Slutför registreringen och hämta aktuell status under Mitt ID.")
                } else {
                    let requests = model.snapshot?.requests ?? []
                    if requests.isEmpty {
                        EmptyPanel(symbol: "checkmark.shield", title: "Inga väntande begäranden", message: "Starta inloggningen hos testtjänsten. Hämta sedan begäran här.")
                    }
                    ForEach(requests) { request in
                        Button { model.focusedRequest = request } label: {
                            VStack(alignment: .leading, spacing: 10) {
                                Label(request.relyingParty, systemImage: "building.2").font(.headline)
                                Text(request.purpose).font(.subheadline)
                                HStack { Text("Kod \(request.code)").monospaced(); Spacer(); Image(systemName: "chevron.right") }.font(.caption)
                            }.padding(20).frame(maxWidth: .infinity, alignment: .leading).background(.white, in: RoundedRectangle(cornerRadius: 20))
                        }.buttonStyle(.plain).disabled(request.expired)
                    }
                    PrimaryButton(title: "Hämta begäranden", symbol: "arrow.clockwise") { model.refresh() }
                    Button { scanner = true } label: { Label("Skanna en QR-kod", systemImage: "qrcode.viewfinder") }
                        .padding().accessibilityIdentifier("requests.scan")
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Har du en begärandelänk?").font(.footnote.bold())
                        TextField("openid://request/…", text: $link).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .textFieldStyle(.roundedBorder).accessibilityIdentifier("requests.link")
                        Button("Öppna begäran") { if let url = URL(string: link) { model.open(url) } else { model.error = "Ogiltig länk." } }
                    }
                }
                if model.busy { ProgressView() }
            }.padding(24)
        }.background(Palette.paper).navigationTitle("Legitimera").disabled(model.busy)
            .sheet(isPresented: $scanner) { QRScanView { url in scanner = false; model.open(url) } }
    }
}
struct ApprovalView: View {
    @EnvironmentObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    let request: WalletRequest
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 25) {
                Label("BEGÄRAN OM LEGITIMERING", systemImage: "arrow.down.left").font(.caption.bold()).foregroundStyle(Palette.muted)
                Text(request.relyingParty).font(.largeTitle.bold())
                Text(request.purpose).font(.title3)
                VStack(alignment: .leading, spacing: 12) {
                    Text("Kontrollkod").font(.subheadline)
                    Text(request.code).font(.system(size: 40, weight: .medium, design: .monospaced)).tracking(7)
                    Text("Koden ska vara samma som hos tjänsten där du startade inloggningen.").font(.footnote)
                }.padding(24).frame(maxWidth: .infinity, alignment: .leading).background(Palette.mint, in: RoundedRectangle(cornerRadius: 20))
                Label("Godkänn bara en inloggning du själv startat.", systemImage: "hand.raised").font(.subheadline)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let remaining = max(0, Int(request.expiresAt - context.date.timeIntervalSince1970))
                    Text(remaining > 0 ? "Begäran går ut om \(remaining) sekunder" : "Begäran har gått ut").font(.caption).foregroundStyle(Palette.muted)
                    PrimaryButton(title: "Godkänn", symbol: "faceid") { model.decide(request, approve: true) }.disabled(remaining == 0 || model.busy)
                }
                Button("Neka begäran", role: .destructive) { model.decide(request, approve: false) }.frame(maxWidth: .infinity).disabled(model.busy)
                if model.busy { ProgressView("Bekräftar…").frame(maxWidth: .infinity) }
            }.padding(24)
        }.background(Palette.paper).navigationTitle("Kontrollera begäran").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Stäng") { dismiss() }.disabled(model.busy) } }
            .interactiveDismissDisabled(model.busy)
    }
}
struct ActivityView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        List {
            if !model.unlocked || model.snapshot == nil {
                EmptyPanel(symbol: "clock", title: "Din aktivitet", message: "Lås upp och uppdatera ditt ID för att se serverns senaste händelser.").listRowBackground(Color.clear)
            } else if model.snapshot?.events.isEmpty == true {
                Text("Inga händelser ännu.")
            }
            ForEach(model.snapshot?.events ?? []) { event in
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: event.kind == "REVOKED" ? "xmark.shield" : "checkmark.circle").font(.title3).foregroundStyle(Palette.ink)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(event.title).font(.subheadline.weight(.medium))
                        Text(Date(timeIntervalSince1970: event.time), format: .dateTime.day().month().hour().minute()).font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.vertical, 8)
            }
        }.scrollContentBackground(.hidden).background(Palette.paper).navigationTitle("Aktivitet")
            .toolbar { if model.unlocked && model.credential != nil { Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }.disabled(model.busy) } }
    }
}
struct SettingsView: View {
    @EnvironmentObject var model: WalletModel
    @State private var revoke = false
    @State private var forget = false
    var body: some View {
        List {
            Section("Ditt openID") {
                if !model.unlocked { Button { model.unlock() } label: { Label("Lås upp openID", systemImage: "faceid") } }
                else {
                    Button { model.settingsPresented = true } label: { Label("Anslutning", systemImage: "network") }
                    if let configuration = model.configuration { Text(configuration.origin).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    if let credential = model.credential {
                        LabeledContent("Enhet", value: "Den här telefonen")
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Registreringsreferens").font(.caption)
                            Text(credential.id).font(.caption2.monospaced()).textSelection(.enabled)
                        }
                    }
                    Button { model.lock() } label: { Label("Lås appen", systemImage: "lock") }
                }
            }
            if model.unlocked && model.credential != nil {
                Section("Spärr och ny telefon") {
                    Button("Spärra mitt ID", role: .destructive) { revoke = true }.disabled(model.busy)
                    Text("Spärren är permanent och stoppar nya inloggningar. Ett nytt ID kräver en ny registrering.").font(.caption).foregroundStyle(.secondary)
                    if model.snapshot?.state == .revoked || model.snapshot?.state == .expired {
                        Button("Ta bort nyckeln från telefonen", role: .destructive) { forget = true }
                    }
                    NavigationLink("Jag har förlorat min telefon") { RecoveryView() }
                }
            }
            Section("Om") {
                NavigationLink("Så fungerar det") { GuideView() }
                NavigationLink("Personuppgifter och säkerhet") { PrivacyView() }
                LabeledContent("Version", value: "0.2 · Privat pilot")
            }
        }.scrollContentBackground(.hidden).background(Palette.paper).navigationTitle("Inställningar")
            .confirmationDialog("Spärra detta ID permanent?", isPresented: $revoke, titleVisibility: .visible) {
                Button("Spärra permanent", role: .destructive) { model.revoke() }
            } message: { Text("Pågående godkännanden blir också ogiltiga. Du bekräftar med Face ID, Touch ID eller enhetskod.") }
            .confirmationDialog("Ta bort den spärrade eller utgångna nyckeln?", isPresented: $forget, titleVisibility: .visible) {
                Button("Ta bort nyckeln", role: .destructive) { do { try model.forgetRevokedCredential() } catch { model.error = error.localizedDescription } }
            } message: { Text("Nyckeln kan inte återställas. Därefter kan du börja en ny passregistrering.") }
    }
}
struct ConnectionView: View {
    @EnvironmentObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @State private var origin = ""
    @State private var pairing = ""
    @State private var error: String?
    var body: some View {
        Form {
            Section {
                Text("Anslut till verifieringsservern för din privata pilot. Du får adressen och kopplingskoden från den som startar servern.")
            }
            Section("Server") {
                TextField("https://server:8765", text: $origin).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("connection.origin")
                    .disabled(model.credential != nil)
                SecureField("Kopplingskod", text: $pairing).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("connection.pairing")
            }
            if let error { Text(error).foregroundStyle(.red).accessibilityIdentifier("connection.error") }
            Section {
                Button("Spara anslutning") {
                    do { try model.saveConfiguration(origin: origin, pairing: pairing); dismiss() }
                    catch { self.error = error.localizedDescription }
                }.accessibilityIdentifier("connection.save")
            } footer: { Text("Anslutningen kräver HTTPS med ett certifikat som telefonen litar på. Koden lagras i telefonens nyckelring.") }
        }.navigationTitle("Anslutning").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Stäng") { dismiss() } } }
            .onAppear { origin = model.configuration?.origin ?? ""; pairing = model.configuration?.pairing ?? "" }
    }
}
struct EnrollmentView: View {
    @ObservedObject var flow: VerificationFlow
    @EnvironmentObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @State private var consent = false
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    HStack(spacing: 6) {
                        ForEach(0..<4) { index in Capsule().fill(index <= flow.phase ? Palette.ink : Palette.ink.opacity(0.12)).frame(height: 4) }
                    }.accessibilityLabel("Steg \(flow.phase+1) av 4")
                    Text(flow.completed ? "Kontrollen är klar" : flow.cameraVisible ? "Titta mot kameran" : flow.busy ? "Vi läser ditt pass" : "Börja med ditt pass")
                        .font(.largeTitle.bold())
                    if !flow.busy && !flow.completed {
                        Text("Du behöver ditt giltiga pass och en lugn plats med bra ljus. Uppgifterna nedan öppnar chipets skyddade kanal.").foregroundStyle(Palette.muted)
                        VStack(spacing: 14) {
                            TextField("Passnummer", text: $flow.documentNumber).textInputAutocapitalization(.characters).autocorrectionDisabled()
                            TextField("Födelsedatum · ÅÅMMDD", text: $flow.birth).keyboardType(.numberPad)
                            TextField("Giltigt till · ÅÅMMDD", text: $flow.expiry).keyboardType(.numberPad)
                        }.textFieldStyle(.roundedBorder)
                        Toggle(isOn: $consent) {
                            Text("Jag vill skicka passets chipuppgifter och tre kamerabilder till min verifieringsserver för denna kontroll.").font(.footnote)
                        }.tint(Palette.ink)
                        PrimaryButton(title: "Läs passet", symbol: "wave.3.right") { flow.start() }.disabled(!consent)
                    }
                    if flow.cameraVisible {
                        CameraPreview(session: flow.camera.session).frame(height: 370).clipShape(RoundedRectangle(cornerRadius: 24))
                        Text("Håll ansiktet synligt och telefonen stilla. Tre nya bilder tas automatiskt.").font(.subheadline)
                    } else if flow.busy {
                        EmptyPanel(symbol: "wave.3.right", title: "Håll telefonen mot passet", message: "Följ anvisningarna i NFC-fönstret. Därefter öppnas kameran.")
                        ProgressView().frame(maxWidth: .infinity)
                    }
                    if flow.completed { Image(systemName: "checkmark.circle.fill").font(.system(size: 64)).foregroundStyle(Palette.ink) }
                    Text(flow.status).font(.subheadline).accessibilityAddTraits(.updatesFrequently)
                    if flow.completed {
                        PrimaryButton(title: "Till mitt ID") { dismiss(); model.refresh() }
                    }
                }.padding(24)
            }.background(Palette.paper).navigationTitle("Registrera").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button(flow.busy ? "Avbryt" : "Stäng") { flow.cancel(); dismiss() } } }
                .interactiveDismissDisabled(flow.busy)
                .onDisappear { flow.cancel() }
        }
    }
}
struct GuideView: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        List {
            Section("1. Registrera") { Text("Läs passets chip och ta nya kamerabilder. Underlaget kontrolleras av servern och binds till telefonens nyckel. Aktivering för den privata piloten sker separat.") }
            Section("2. Legitimera") { Text("Starta inloggningen hos den lokala testtjänsten. Öppna begäran i appen, kontrollera tjänst och kod och välj godkänn eller neka.") }
            Section("3. Ha kontroll") { Text("Se aktuella händelser, lås appen och spärra ditt ID. En spärrad nyckel kan aldrig aktiveras igen.") }
            Section("Den här versionen") { Text("Passkontroll, ansiktsjämförelse och liveness används i en privat teknisk pilot. Modellerna är ännu inte kalibrerade för e-id-utgivning. Appen är inte en godkänd svensk e-legitimation.") }
        }.navigationTitle("Så fungerar det").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Klart") { dismiss() } } }
    }
}
struct RecoveryView: View {
    var body: some View {
        List {
            Section("Spärra först") { Text("Kontakta operatören för din privata pilot så att den förlorade telefonens nyckel spärras på servern. Att radera appen spärrar inte nyckeln.") }
            Section("Registrera den nya telefonen") { Text("Installera appen och gör en ny pass- och personkontroll. Den nya telefonen får en ny nyckel och behöver ett nytt aktiveringsbeslut.") }
            Section("Ingen återställningskod") { Text("Nyckeln exporteras eller synkroniseras inte. E-post, lösenord och gamla säkerhetskopior kan inte återaktivera en spärrad nyckel.") }
        }.navigationTitle("Förlorad telefon")
    }
}
struct PrivacyView: View {
    var body: some View {
        List {
            Section("På telefonen") { Text("Serveradress, kopplingskod och telefonens skyddade nyckelreferens lagras i nyckelringen för denna enhet. Passnummer, chipdata och bilder sparas inte av appen.") }
            Section("På verifieringsservern") { Text("Pass- och kameraunderlag behandlas i minnet. Appens pilotregister sparar publik nyckel, status och händelser. Det sparar inga passbilder eller ansiktsmallar. Operatören ansvarar för datorn och lagringstiderna.") }
            Section("Ditt godkännande") { Text("En inloggning är bunden till den begäran som visas. Du bekräftar med Face ID, Touch ID eller enhetskod. Appen låses när den går till bakgrunden.") }
            Section("Gränser") { Text("App Attest är inget bevis för kamerans fysiska verklighet. Komprometterade enheter och avancerade angrepp behöver fortsatt utvärdering. Pilotens lokala administratör kan aktivera och spärra nycklar; fullständig separation av roller är inte införd.") }
        }.navigationTitle("Integritet").navigationBarTitleDisplayMode(.inline)
    }
}
