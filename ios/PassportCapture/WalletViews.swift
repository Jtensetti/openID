import SwiftUI

struct WalletRootView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        TabView(selection: $model.selectedTab) {
            NavigationStack { HomeView() }.tabItem { Label("Mitt ID", systemImage: "person.crop.rectangle") }.tag(0)
            NavigationStack { RequestsView() }.tabItem { Label("Legitimera", systemImage: "qrcode.viewfinder") }.tag(1)
            NavigationStack { ActivityView() }.tabItem { Label("Aktivitet", systemImage: "clock") }.tag(2)
            NavigationStack { SettingsView() }.tabItem { Label("Inställningar", systemImage: "slider.horizontal.3") }.tag(3)
        }
        .tint(Palette.tint)
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
    @Environment(\.dynamicTypeSize) private var textSize
    var body: some View {
        let layout = textSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: 9)) : AnyLayout(HStackLayout(spacing: 9))
        layout {
            Image(systemName: "circle.hexagongrid.fill").font(.title2).foregroundStyle(Palette.ink)
            Text("openID").font(.title2.weight(.bold)).foregroundStyle(Palette.ink)
            if !textSize.isAccessibilitySize { Spacer() }
            Text("PRIVAT PILOT").font(.caption2.monospaced().weight(.bold))
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
            HStack { Text(title).font(.headline).fixedSize(horizontal: false, vertical: true); Spacer(); Image(systemName: symbol).accessibilityHidden(true) }
                .padding(19).foregroundStyle(Palette.actionText).background(Palette.actionBackground, in: RoundedRectangle(cornerRadius: 18))
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
                Text("Mitt ID").font(.largeTitle.bold()).accessibilityIdentifier("home.heading")
                IdentityCard()
                if model.configuration == nil || model.configuration?.isPublicBeta == true {
                    Text(model.revocationProof == nil ? "Testservern är öppen dygnet runt till och med 30 november 2026 och stängs av den 1 december kl. 00.00 svensk tid. Registrering, legitimering och spärr kräver att testservern är igång." : "Testservern är öppen dygnet runt till och med 30 november 2026 och stängs av den 1 december kl. 00.00 svensk tid. Din sparade spärrkod kan användas även när testservern är avstängd, med internetanslutning.")
                        .font(.subheadline).foregroundStyle(Palette.muted).accessibilityIdentifier("home.betaHours")
                }
                if let state = model.credentialState, state != .active {
                    Text(state.guidance).font(.subheadline).foregroundStyle(Palette.muted)
                }
                VStack(spacing: 12) {
                    if !model.unlocked {
                        PrimaryButton(title: "Öppna openID", symbol: "faceid") { model.unlock() }
                            .accessibilityIdentifier("home.unlock").disabled(model.busy)
                    } else if model.configuration == nil {
                        PrimaryButton(title: "Anslut till servern") { model.settingsPresented = true }
                    } else if model.credential == nil {
                        PrimaryButton(title: "Registrera med ditt pass", symbol: "person.crop.rectangle.badge.plus") { model.beginRegistration() }
                            .accessibilityIdentifier("home.register").disabled(!model.canResumeRegistration)
                    } else if model.canForgetCredential {
                        PrimaryButton(title: "Förbered ett nytt ID", symbol: "person.crop.rectangle.badge.plus") { model.selectedTab = 3 }
                    } else if model.snapshot?.state == .active {
                        PrimaryButton(title: "Legitimera mig", symbol: "qrcode.viewfinder") { model.selectedTab = 1 }
                            .accessibilityIdentifier("home.identify").disabled(model.busy)
                        if model.snapshot?.securityCode?.set == false {
                            NavigationLink { SecurityCodeView() } label: {
                                Label("Välj säkerhetskod för stora åtaganden", systemImage: "lock.shield").frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                            }.accessibilityIdentifier("home.securityCode")
                        }
                        Button("Hämta status") { model.refresh() }.frame(minHeight: 44).disabled(model.busy)
                    } else {
                        PrimaryButton(title: "Hämta status", symbol: "arrow.clockwise") { model.refresh() }.disabled(model.busy)
                        if model.canResumeRegistration {
                            Button("Fortsätt registreringen") { model.beginRegistration() }.font(.subheadline)
                                .accessibilityIdentifier("home.resumeRegistration")
                            Text("Om registreringen avbröts kan du fortsätta med samma nyckel. Passet och ansiktskontrollen krävs fortfarande.")
                                .font(.footnote).foregroundStyle(Palette.muted)
                        }
                    }
                    if let message = model.statusMessage { Text(message).font(.subheadline).foregroundStyle(Palette.muted).accessibilityIdentifier("home.statusMessage") }
                    if model.busy { ProgressView("Hämtar status…").accessibilityIdentifier("home.progress") }
                }
                Button { guide = true } label: {
                    HStack { Text("Så fungerar openID").font(.subheadline.weight(.medium)); Spacer(); Image(systemName: "arrow.up.right") }
                }.accessibilityIdentifier("home.guide")
            }.padding(24)
        }.background(Palette.paper).foregroundStyle(Palette.ink)
            .toolbar(.hidden, for: .navigationBar)
            .sheet(isPresented: $guide) { NavigationStack { GuideView() } }
    }
}
struct IdentityCard: View {
    @EnvironmentObject var model: WalletModel
    @Environment(\.dynamicTypeSize) private var textSize
    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack {
                Text("openID").font(.system(size: 22, weight: .semibold, design: .rounded))
                Spacer()
                Image(systemName: "wave.3.right").font(.title2).rotationEffect(.degrees(90))
            }
            let layout = textSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: 16)) : AnyLayout(HStackLayout(alignment: .center, spacing: 16))
            layout {
                if let portrait = model.snapshot?.identity?.portraitJpeg,
                   let data = Data(base64Encoded: portrait), let image = UIImage(data: data) {
                    Image(uiImage: image).resizable().scaledToFill().frame(width: 76, height: 96)
                        .clipShape(RoundedRectangle(cornerRadius: 12)).accessibilityLabel("Passfoto")
                } else {
                    Image(systemName: "person.crop.rectangle").font(.system(size: 38, weight: .ultraLight))
                        .frame(width: 68, height: 68).background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 18))
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text(model.snapshot?.identity?.displayName ?? (model.unlocked ? (model.credential != nil ? "Mitt ID" : "Inget ID registrerat") : "Låst")).font(.title2.weight(.medium))
                    if let identity = model.snapshot?.identity {
                        Text("Född enligt passet · \(identity.birthDateMrz)").font(.caption)
                        if let number = identity.passportPersonalNumber {
                            Text("Identitetsnummer i passet · \(number)").font(.caption).textSelection(.enabled)
                            Text("Avläst från passets chip. Inte kontrollerat mot folkbokföringen.").font(.caption2)
                        }
                    }
                    HStack(spacing: 6) {
                        Image(systemName: model.credentialState == .active ? "checkmark.circle.fill" : "info.circle").accessibilityHidden(true)
                        Text(model.credentialState?.title ?? (model.unlocked ? (model.credential != nil ? (model.busy ? "Hämtar status…" : "Status inte hämtad") : "Registrera med ditt pass") : "Lås upp för att se status"))
                            .font(.caption).fixedSize(horizontal: false, vertical: true)
                    }.foregroundStyle(Palette.mint)
                }
            }
            HStack {
                Text("ENHETSBUNDET").font(.system(size: 9, weight: .medium, design: .monospaced)).tracking(2)
                Spacer()
                Text(model.snapshot.map { "ID · " + String($0.credentialId.suffix(6)).uppercased() } ?? "••••  ••••")
                    .font(.system(size: 11, design: .monospaced))
            }.foregroundStyle(.white.opacity(0.8))
        }
        .padding(24).foregroundStyle(.white)
        .background(LinearGradient(colors: [Palette.cardStart, Palette.cardEnd], startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: 25))
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
                .frame(width: 92, height: 92).background(Palette.accentSurface, in: Circle())
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
                    EmptyPanel(symbol: "lock", title: "Legitimera dig", message: "Lås upp för att se dina begäranden.")
                    PrimaryButton(title: "Öppna openID", symbol: "faceid") { model.unlock() }
                } else if model.snapshot == nil && model.busy {
                    EmptyPanel(symbol: "hourglass", title: "Hämtar status…", message: "Vi kontrollerar ditt ID innan du legitimerar dig.")
                } else if model.snapshot?.state != .active {
                    EmptyPanel(symbol: "person.crop.rectangle", title: model.snapshot?.state.title ?? "Status inte hämtad", message: model.snapshot?.state.guidance ?? model.statusMessage ?? "Gå till Mitt ID och hämta aktuell status.")
                    PrimaryButton(title: "Till Mitt ID") { model.selectedTab = 0 }
                } else {
                    if let message = model.decisionMessage {
                        Text(message).font(.subheadline).foregroundStyle(Palette.ink).padding().frame(maxWidth: .infinity, alignment: .leading).background(Palette.accentSurface, in: RoundedRectangle(cornerRadius: 12)).accessibilityIdentifier("requests.decision")
                    }
                    PrimaryButton(title: "Skanna en QR-kod", symbol: "qrcode.viewfinder") { scanner = true }
                        .accessibilityIdentifier("requests.scan")
                    Text("På samma telefon? Välj Öppna openID på tjänstens inloggningssida. På en annan skärm? Skanna QR-koden här.")
                        .font(.subheadline).foregroundStyle(Palette.muted)
                    let requests = model.snapshot?.requests ?? []
                    if requests.isEmpty {
                        EmptyPanel(symbol: "checkmark.shield", title: "Inga väntande begäranden", message: "Starta en inloggning hos tjänsten och skanna QR-koden.")
                    }
                    ForEach(requests) { request in
                        Button { model.focusedRequest = request } label: {
                            VStack(alignment: .leading, spacing: 10) {
                                Label(request.relyingParty, systemImage: request.isSigning ? "signature" : "building.2").font(.headline)
                                Text(request.isSigning ? "Underskrift" : request.purpose).font(.subheadline)
                                HStack { Text("Kod \(request.code)").monospaced(); Spacer(); Image(systemName: "chevron.right") }.font(.caption)
                            }.padding(20).frame(maxWidth: .infinity, alignment: .leading).background(Palette.surface, in: RoundedRectangle(cornerRadius: 20))
                        }.buttonStyle(.plain).disabled(request.expired)
                    }
                    Button("Hämta begäranden") { model.refresh() }.frame(minHeight: 44)
                    DisclosureGroup("Öppna en länk i stället") {
                        Text("Klistra in en openID-länk från tjänsten. Kontrollera sedan mottagare och kod innan du godkänner.").font(.subheadline)
                        TextField("openid://request/…", text: $link).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .textFieldStyle(.roundedBorder).accessibilityLabel("Länk till legitimering").accessibilityIdentifier("requests.link")
                        Button("Öppna begäran") { if let url = URL(string: link) { model.open(url) } else { model.error = "Ogiltig länk." } }
                    }
                }
                if model.busy { ProgressView() }
            }.padding(24)
        }.background(Palette.paper).navigationTitle("Legitimera").disabled(model.busy)
            .sheet(isPresented: $scanner) { QRScanView { url in scanner = false; model.open(url) } }
    }
}
struct ControlCodeView: View {
    let code: String
    @Environment(\.dynamicTypeSize) private var textSize
    var body: some View {
        Group {
            if textSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: 4) {
                    Text(String(code.prefix(3)))
                    Text(String(code.suffix(3)))
                }
            } else { Text(code) }
        }.font(.largeTitle.monospaced().weight(.medium))
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Kontrollkod")
            .accessibilityValue(code.map(String.init).joined(separator: ", "))
            .accessibilityIdentifier("approval.code")
    }
}
/// Six digits, masked; only digits are kept and at most six.
struct SecurityCodeField: View {
    let title: String
    @Binding var code: String
    var body: some View {
        SecureField(title, text: $code)
            .keyboardType(.numberPad).font(.title2.monospacedDigit())
            .onChange(of: code) { value in
                let digits = String(value.unicodeScalars.filter { (48...57).contains($0.value) }.map(Character.init).prefix(6))
                if digits != value { code = digits }
            }
            .accessibilityLabel(title)
    }
}
struct SecurityCodeView: View {
    @EnvironmentObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var repeated = ""
    private var status: SecurityCodeStatus? { model.snapshot?.securityCode }
    var body: some View {
        Form {
            if status?.locked == true {
                Section("Spärrad") {
                    Text(WalletError.securityCode("PIN_LOCKED", 0).localizedDescription)
                }
            } else {
                Section {
                    Text("Tjänster kan kräva säkerhetskoden för stora åtaganden, till exempel lån eller avtal med höga belopp. Face ID räcker för det vardagliga.")
                    Text("Koden kontrolleras av openID-servern. Fem fel i rad spärrar den; då måste du registrera ditt ID på nytt med passet.").font(.footnote).foregroundStyle(.secondary)
                }
                if status?.set == true {
                    Section("Nuvarande kod") { SecurityCodeField(title: "Nuvarande säkerhetskod", code: $current) }
                }
                Section(status?.set == true ? "Ny kod" : "Välj kod") {
                    SecurityCodeField(title: "Sex siffror", code: $new)
                    SecurityCodeField(title: "Upprepa koden", code: $repeated)
                    Text("Använd inte telefonens kod, ditt födelsedatum eller följder som 123456.").font(.footnote).foregroundStyle(.secondary)
                }
                if let message = model.securityCodeMessage {
                    Text(message).font(.callout).foregroundStyle(Palette.error).accessibilityIdentifier("securityCode.message")
                }
                Section {
                    Button(status?.set == true ? "Byt säkerhetskod" : "Spara säkerhetskod") {
                        model.setSecurityCode(current: status?.set == true ? current : nil, new: new)
                    }.disabled(model.busy || !SecurityCode.valid(new) || new != repeated || (status?.set == true && !SecurityCode.valid(current)))
                    if !repeated.isEmpty && repeated.count == 6 && new != repeated { Text("Koderna är inte lika.").font(.footnote).foregroundStyle(Palette.error) }
                    if model.busy { ProgressView() }
                }
            }
        }.navigationTitle("Säkerhetskod").navigationBarTitleDisplayMode(.inline)
            .onAppear { model.clearSecurityCodeMessage() }
            .onChange(of: model.unlocked) { unlocked in
                if !unlocked { current = ""; new = ""; repeated = ""; dismiss() }
            }
            .onDisappear { current = ""; new = ""; repeated = "" }
            .onChange(of: model.statusMessage) { message in
                if message != nil && model.snapshot?.securityCode?.set == true && model.securityCodeMessage == nil { dismiss() }
            }
    }
}
struct ApprovalView: View {
    @EnvironmentObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @State private var securityCode = ""
    let request: WalletRequest
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 25) {
                Label(request.isSigning ? "BEGÄRAN OM UNDERSKRIFT" : "BEGÄRAN OM LEGITIMERING", systemImage: request.isSigning ? "signature" : "arrow.down.left")
                    .font(.caption.bold()).foregroundStyle(Palette.muted)
                Text(request.relyingParty).font(.largeTitle.bold())
                if let text = request.signMessage {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Det här skriver du under").font(.subheadline.weight(.semibold))
                        // Plain text only, never interpreted as markdown or links.
                        Text(verbatim: text).font(.body).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                            .accessibilityIdentifier("approval.signMessage")
                    }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Palette.surface, in: RoundedRectangle(cornerRadius: 20))
                        .overlay(RoundedRectangle(cornerRadius: 20).stroke(Palette.ink, lineWidth: 2))
                        .accessibilityElement(children: .combine)
                }
                Text(request.purpose).font(request.isSigning ? .subheadline : .title3)
                VStack(alignment: .leading, spacing: 12) {
                    Text("Kontrollkod").font(.subheadline)
                    ControlCodeView(code: request.code)
                    Text("Kontrollera att samma kod visas hos tjänsten.").font(.footnote)
                }.padding(24).frame(maxWidth: .infinity, alignment: .leading).foregroundStyle(Palette.ink).background(Palette.accentSurface, in: RoundedRectangle(cornerRadius: 20))
                Label(request.isSigning ? "Skriv bara under om du själv startat underskriften och texten stämmer med dokumentet hos tjänsten." : "Godkänn bara en inloggning du själv startat.", systemImage: "hand.raised").font(.subheadline)
                if request.needsSecurityCode {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Tjänsten kräver din säkerhetskod", systemImage: "lock.shield").font(.headline)
                        if model.snapshot?.securityCode?.set == false {
                            Text("Du har ingen säkerhetskod ännu. Välj en först; begäran gäller i två minuter.").font(.subheadline)
                            NavigationLink("Välj säkerhetskod") { SecurityCodeView() }
                        } else {
                            SecurityCodeField(title: "Säkerhetskod, 6 siffror", code: $securityCode).accessibilityIdentifier("approval.securityCode")
                            Text("Utöver Face ID. Fem fel i rad spärrar koden.").font(.footnote).foregroundStyle(Palette.muted)
                        }
                        if let message = model.securityCodeMessage {
                            Text(message).font(.callout).foregroundStyle(Palette.error).accessibilityIdentifier("approval.securityCodeMessage")
                        }
                    }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Palette.surface, in: RoundedRectangle(cornerRadius: 20))
                }
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let remaining = max(0, Int(request.expiresAt - context.date.timeIntervalSince1970))
                    Text(remaining > 0 ? "Begäran går ut om \(remaining) sekunder" : "QR-koden har gått ut. Starta en ny inloggning på testsidan och skanna den nya koden.").font(.caption).foregroundStyle(Palette.muted)
                    PrimaryButton(title: request.isSigning ? "Skriv under" : "Godkänn", symbol: request.isSigning ? "signature" : "faceid") {
                        model.decide(request, approve: true, securityCode: request.needsSecurityCode ? securityCode : nil)
                        securityCode = ""
                    }
                        .disabled(remaining == 0 || model.busy || (request.needsSecurityCode && !SecurityCode.valid(securityCode)))
                        .accessibilityIdentifier("approval.approve")
                }
                if model.busy { ProgressView("Bekräftar…").frame(maxWidth: .infinity) }
            }.padding(24)
        }.background(Palette.paper).navigationTitle("Kontrollera begäran").navigationBarTitleDisplayMode(.inline)
            // Keep refusal reachable without scrolling through a signature or dismissing the keyboard.
            .safeAreaInset(edge: .bottom, spacing: 0) {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Button(role: .destructive) {
                        securityCode = ""
                        model.decide(request, approve: false)
                    } label: {
                        Text(request.isSigning ? "Avböj underskrift" : "Neka begäran")
                            .font(.headline).fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .accessibilityIdentifier("approval.reject")
                    .disabled(request.expiresAt <= context.date.timeIntervalSince1970 || model.busy)
                    .padding(.horizontal, 24).padding(.vertical, 8)
                    .background(Palette.paper)
                    .overlay(alignment: .top) { Divider() }
                }
            }
            .onAppear { model.clearSecurityCodeMessage() }
            .onChange(of: model.unlocked) { unlocked in if !unlocked { securityCode = ""; dismiss() } }
            .onDisappear { securityCode = "" }
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Stäng") { dismiss() }.disabled(model.busy) } }
            .interactiveDismissDisabled(model.busy)
    }
}
struct ActivityView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        List {
            if !model.unlocked || model.snapshot == nil {
                EmptyPanel(symbol: "clock", title: "Din aktivitet", message: "Lås upp och uppdatera ditt ID för att se händelser.").listRowBackground(Color.clear)
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
            .toolbar { if model.unlocked && model.credential != nil { Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }.accessibilityLabel("Hämta senaste aktivitet").disabled(model.busy) } }
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
                    if model.configuration?.isPublicBeta == true {
                        Label("Ansluten till openID beta", systemImage: "network")
                        Text("Anslutningen sköts automatiskt. VPN behövs inte. Testservern är öppen dygnet runt till och med 30 november 2026 och stängs av den 1 december kl. 00.00 svensk tid.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        Button { model.settingsPresented = true } label: { Label("Anslutning", systemImage: "network") }
                        if let configuration = model.configuration { Text(configuration.origin).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    }
                    if let credential = model.credential {
                        LabeledContent("Enhet", value: "Den här telefonen")
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Registrerings-ID").font(.caption)
                            Text(credential.id).font(.caption2.monospaced()).textSelection(.enabled)
                        }
                    }
                    Button { model.lock() } label: { Label("Lås appen", systemImage: "lock") }
                }
            }
            if model.unlocked && model.credential != nil && model.snapshot?.state == .active, let code = model.snapshot?.securityCode {
                Section("Säkerhetskod") {
                    NavigationLink(code.locked ? "Säkerhetskoden är spärrad" : code.set ? "Byt säkerhetskod" : "Välj säkerhetskod") { SecurityCodeView() }
                    if code.set && !code.locked && code.attemptsRemaining < SecurityCode.attempts {
                        Text("\(code.attemptsRemaining) försök kvar innan koden spärras.").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if model.unlocked && model.credential != nil {
                Section("Spärr och ny telefon") {
                    Button("Spärra mitt ID", role: .destructive) { revoke = true }.disabled(!model.canRevoke)
                    if let message = model.statusMessage { Text(message).font(.callout) }
                    if let proof = model.revocationProof {
                        Text("Spärr fungerar dygnet runt när du har internetanslutning, även när testservern är stängd.").font(.caption)
                        DisclosureGroup("Spara din spärrkod") {
                            Text("Spara koden på en säker plats utanför telefonen. Den kan bara spärra ditt ID, aldrig aktivera eller återställa det.")
                            Text(proof.code).font(.caption.monospaced()).textSelection(.enabled)
                            Link("Öppna spärrsidan", destination: RevocationProof.endpoint)
                        }
                    }
                    if model.canForgetCredential {
                        Button("Ta bort nyckeln från telefonen", role: .destructive) { forget = true }
                            .accessibilityIdentifier("settings.forgetCredential")
                    } else if model.snapshot?.state == .expired {
                        Text("Spärra även ett utgånget ID innan du tar bort nyckeln. Då bevaras möjligheten att bekräfta spärren och registrera på nytt.").font(.caption)
                    }
                    NavigationLink("Jag har förlorat min telefon") { RecoveryView() }
                }
            }
            Section("Kameraprov") {
                NavigationLink("Prova ansiktskameran") { CameraCheckView() }
            }
            Section("Om") {
                NavigationLink("Så fungerar det") { GuideView() }
                NavigationLink("Personuppgifter och säkerhet") { PrivacyView() }
                LabeledContent("Version", value: AppBuild.current.display)
                    .accessibilityElement(children: .ignore).accessibilityLabel("Version")
                    .accessibilityValue(AppBuild.current.display).accessibilityIdentifier("settings.version")
            }
        }.scrollContentBackground(.hidden).background(Palette.paper).navigationTitle("Inställningar")
            .confirmationDialog("Spärra detta ID permanent?", isPresented: $revoke, titleVisibility: .visible) {
                Button("Spärra permanent", role: .destructive) { model.revoke() }
            } message: { Text("Pågående och nya inloggningar stoppas. Du behöver registrera dig på nytt för att få ett nytt ID.") }
            .confirmationDialog("Ta bort den spärrade nyckeln?", isPresented: $forget, titleVisibility: .visible) {
                Button("Ta bort nyckeln", role: .destructive) { do { try model.forgetRevokedCredential() } catch { model.error = error.localizedDescription } }
            } message: { Text("ID:t är redan spärrat. Nyckeln kan inte återställas. Därefter kan du registrera ett nytt ID med passet.") }
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
                Text("Ange adress och kopplingskod från serverns terminal.")
            }
            Section("Server") {
                TextField("https://server:8765", text: $origin).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("connection.origin")
                    .disabled(model.credential != nil)
                SecureField("Kopplingskod", text: $pairing).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("connection.pairing")
            }
            if let error { Text(error).foregroundStyle(Palette.error).accessibilityIdentifier("connection.error") }
            Section {
                Button("Spara anslutning") {
                    do { try model.saveConfiguration(origin: origin, pairing: pairing); dismiss() }
                    catch { self.error = error.localizedDescription }
                }.accessibilityIdentifier("connection.save")
            } footer: { Text("Telefonen måste lita på serverns HTTPS-certifikat.") }
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
    @State private var scanPassport = false
    @State private var cameraPractice = false
    @State private var scanned = false
    @State private var inputIssue: PassportAccessKey.Field?
    @FocusState private var focusedField: PassportAccessKey.Field?
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    HStack(spacing: 6) {
                        ForEach(0..<4) { index in Capsule().fill(index <= flow.phase ? Palette.ink : Palette.ink.opacity(0.12)).frame(height: 4) }
                    }.accessibilityLabel("Steg \(flow.phase+1) av 4")
                    Text(flow.failed ? "Kontrollen stannade" : flow.busy || flow.completed ? flow.stepTitle : "Registrera med pass")
                        .font(.largeTitle.bold())
                    if !flow.busy && !flow.completed && !flow.failed {
                        Text("Du börjar med passuppgifterna. Sedan läser vi chipet och tar tre ansiktsbilder.").font(.subheadline).foregroundStyle(Palette.muted)
                        DisclosureGroup("Förbered dig innan du börjar") {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("1. Ha ditt svenska pass och din iPhone redo. Andra utfärdarländer är ännu inte verifierade i piloten.")
                                Text("2. Använd stabilt internet. Den publika betan behöver ingen VPN.")
                                Text("3. Lägg passet plant. Telefonens överkant ska hållas mot passet vid två läsningar.")
                                Text("4. Sitt eller stå bekvämt med jämnt ljus. Du kan stödja telefonen när du tar ansiktsbilder.")
                                Button("Prova kameran först – utan att skicka bilder") { focusedField = nil; cameraPractice = true }
                            }.font(.subheadline).padding(.top, 8)
                        }.accessibilityIdentifier("enrollment.prepare")
                        PrimaryButton(title: "Skanna passuppgifter", symbol: "doc.viewfinder") { scanPassport = true }
                        if scanned { Label("Uppgifterna är inlästa. Kontrollera dem mot passet.", systemImage: "checkmark.circle.fill").font(.subheadline) }
                        Text("Du kan också fylla i eller rätta uppgifterna nedan. Chipet läses i två omgångar: först passuppgifterna, sedan chipets äkthet.").font(.footnote).foregroundStyle(Palette.muted)
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Passnummer").font(.headline)
                            TextField("Som det står i passet", text: $flow.documentNumber).textInputAutocapitalization(.characters).autocorrectionDisabled()
                                .accessibilityLabel("Passnummer").accessibilityIdentifier("enrollment.number").focused($focusedField, equals: .number)
                            Text("Födelsedatum").font(.headline)
                            TextField("Sex siffror, till exempel 900516", text: $flow.birth).keyboardType(.numberPad)
                                .accessibilityLabel("Födelsedatum, år månad dag med sex siffror").accessibilityIdentifier("enrollment.birth").focused($focusedField, equals: .birth)
                            Text("Passet är giltigt till").font(.headline)
                            TextField("Sex siffror, till exempel 300516", text: $flow.expiry).keyboardType(.numberPad)
                                .accessibilityLabel("Passets sista giltighetsdag, år månad dag med sex siffror").accessibilityIdentifier("enrollment.expiry").focused($focusedField, equals: .expiry)
                            Text("Skriv år, månad och dag med två siffror vardera. Exempel: 16 maj 2030 blir 300516.").font(.footnote).foregroundStyle(Palette.muted)
                            if let inputIssue {
                                Label(inputIssue.instruction, systemImage: "exclamationmark.circle").font(.subheadline)
                                    .accessibilityIdentifier("enrollment.inputIssue")
                            }
                        }.textFieldStyle(.roundedBorder)
                        Toggle(isOn: $consent) {
                            Text("Jag godkänner att passets chipuppgifter och tre kamerabilder skickas till servern. Namn, födelsedatum, nationalitet och passfoto sparas krypterat för mitt ID.").font(.footnote)
                        }.tint(Palette.tint)
                        if !consent { Text("Läs texten ovan och godkänn överföringen för att fortsätta.").font(.footnote).foregroundStyle(Palette.muted) }
                        PrimaryButton(title: "Läs passet", symbol: "wave.3.right") {
                            inputIssue = PassportAccessKey.invalidField(documentNumber: flow.documentNumber, birth: flow.birth, expiry: flow.expiry)
                            if let inputIssue {
                                focusedField = inputIssue
                                if UIAccessibility.isVoiceOverRunning { UIAccessibility.post(notification: .announcement, argument: inputIssue.instruction) }
                            }
                            else { focusedField = nil; scanned = false; flow.start() }
                        }.disabled(!consent).accessibilityIdentifier("enrollment.read")
                    }
                    if flow.cameraVisible {
                        GuidedCaptureView(camera: flow.camera)
                    } else if flow.readyForCamera {
                        PrimaryButton(title: "Starta ansiktskontrollen", symbol: "person.crop.rectangle") { flow.startCamera() }
                    } else if flow.busy {
                        ProgressView().frame(maxWidth: .infinity)
                    }
                    if flow.passportRead && !flow.completed { Label("Passets uppgifter är lästa", systemImage: "checkmark.circle.fill").font(.subheadline) }
                    if flow.failed { PrimaryButton(title: "Börja om", symbol: "arrow.clockwise") { scanned = false; flow.retry() } }
                    if flow.completed { Image(systemName: "checkmark.circle.fill").font(.system(size: 64)).foregroundStyle(Palette.ink) }
                    if !flow.status.isEmpty { Text(flow.status).font(.subheadline).accessibilityAddTraits(.updatesFrequently) }
                    if flow.completed {
                        PrimaryButton(title: "Till mitt ID") { dismiss(); model.refresh() }
                    }
                }.padding(24)
            }.background(Palette.paper).navigationTitle("Registrera").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button(flow.busy ? "Avbryt" : "Stäng") { flow.cancel(); dismiss() } } }
                .toolbar { ToolbarItemGroup(placement: .keyboard) { Spacer(); Button("Klart") { focusedField = nil } } }
                .sheet(isPresented: $cameraPractice) {
                    NavigationStack {
                        CameraCheckView().toolbar { ToolbarItem(placement: .cancellationAction) { Button("Stäng kameraprovet") { cameraPractice = false } } }
                    }
                }
                .sheet(isPresented: $scanPassport) {
                    PassportScanView { value in
                        flow.documentNumber = value.documentNumber; flow.birth = value.birth; flow.expiry = value.expiry
                        scanned = true; inputIssue = nil
                    }
                }
                .interactiveDismissDisabled(flow.busy)
                .onDisappear { flow.cancel() }
        }
    }
}
struct GuideView: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        List {
            Section("Innan du börjar") { Text("Du behöver ett svenskt pass, en kompatibel iPhone och stabil internetanslutning. Den publika betan ansluter automatiskt utan VPN. Du kan prova ansiktskameran under Inställningar utan att skicka bilder.") }
            Section("Registrera en gång") { Text("Skanna passuppgifterna eller skriv in dem. Läs chipet i två omgångar och följ kamerans instruktioner. I den automatiska betan aktiveras ditt test-ID när kontrollerna är godkända, utan e-post. I andra testmiljöer kan operatörens aktivering behövas. Du behöver inte läsa passet vid varje inloggning.") }
            Section("Legitimera") { Text("Starta inloggningen hos testtjänsten. Skanna QR-koden, kontrollera tjänst och kod och godkänn i appen.") }
            Section("På samma telefon") { Text("Om tjänstens sida går att öppna på telefonen, välj Öppna openID där. Du behöver inte skanna din egen skärm. Pilotens nuvarande testsida öppnas på Macen och används med QR-kod.") }
            Section("Om du blir avbruten") { Text("Appen låses när du lämnar den. Lås upp igen och hämta status. Om du redan godkänt, kontrollera Aktivitet innan du börjar om. En utgången QR-kod kräver en ny inloggning, inte en ny passregistrering.") }
            Section("Behöver du hjälp?") { Text("En hjälpare kan förklara stegen, men du ska själv kontrollera mottagaren och godkänna. Dela inte din enhetskod. Om pass- eller kamerakontrollen inte fungerar för dig, avbryt och kontakta den som ordnade pilottestet. Någon alternativ registreringsmetod finns ännu inte.") }
            Section("Spärra") { Text("Du spärrar ditt ID under Inställningar. Spärren är permanent.") }
            Section("Om openID") { Text("Appen är under utveckling och är inte en godkänd e-legitimation.") }
        }.navigationTitle("Så fungerar det").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Klart") { dismiss() } } }
    }
}
struct RecoveryView: View {
    var body: some View {
        List {
            Section("Spärra först") {
                Text("Har du sparat din spärrkod kan du spärra dygnet runt från en annan telefon eller dator. Saknar du koden, kontakta pilotens operatör. Att radera appen spärrar inte ditt ID.")
                Link("Öppna spärrsidan", destination: RevocationProof.endpoint)
            }
            Section("Ny telefon") { Text("Installera appen och registrera dig på nytt med passet. Appen visar när ditt test-ID är aktiverat. Nyckeln kan inte flyttas mellan telefoner eller återställas från en säkerhetskopia.") }
        }.navigationTitle("Förlorad telefon")
    }
}
struct PrivacyView: View {
    var body: some View {
        List {
            Section("På telefonen") { Text("Serveradress, eventuell kopplingskod och din separata spärrkod lagras i nyckelringen. ID-nyckeln skyddas av telefonen. Appen sparar inte passuppgifter eller bilder.") }
            Section("På servern") { Text("Chipdata och kamerabilder behandlas i minnet. Registret sparar namn, födelsedatum, nationalitet, passets utfärdarland, giltighet, foto och eventuellt personnummer från chipet krypterat samt publik nyckel, status och händelser. Operatören ansvarar för lagringstiderna och kan aktivera eller spärra ditt ID.") }
            Section("När du legitimerar dig") { Text("Appen visar vilken tjänst du loggar in hos och vilka uppgifter du delar. En spärrad nyckel kan inte användas igen.") }
            Section("Godkännande") { Text("Du bekräftar med Face ID, Touch ID eller enhetskod. När en tjänst kräver det anger du även din säkerhetskod. Den kontrolleras av openID-servern och sparas där bara som en kontrollsumma, aldrig i klartext. Spärr kräver aldrig kod. Appen låses när du lämnar den.") }
        }.navigationTitle("Integritet").navigationBarTitleDisplayMode(.inline)
    }
}


struct CameraCheckView: View {
    @StateObject private var camera = CaptureCamera()
    @State private var running = false
    @State private var status = "Prova kameran utan att läsa passet. Bilderna används bara i detta lokala prov och sparas eller skickas inte."
    @State private var task: Task<Void, Never>?
    @Environment(\.scenePhase) private var scenePhase
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                if !running { Text(status).accessibilityAddTraits(.updatesFrequently) }
                if running { GuidedCaptureView(camera: camera, showsDiagnostics: true) }
                else {
                    PrimaryButton(title: "Starta kameraprov", symbol: "camera") {
                        running = true; status = "Följ ovalen och instruktionerna."
                        task = Task { @MainActor in
                            defer { running = false; camera.stop() }
                            do {
                                _ = try await camera.capture()
                                try Task.checkCancellation()
                                status = "Kameraprovet är klart. Tre bilder kunde tas. Det här var ingen identitetskontroll."
                            } catch is CancellationError { status = "Kameraprovet avbröts." }
                            catch { status = error.localizedDescription }
                        }
                    }
                }
            }.padding(24)
        }.navigationTitle("Prova ansiktskameran")
            .onDisappear { task?.cancel(); camera.stop() }
            .onChange(of: scenePhase) { phase in if phase == .background { task?.cancel(); camera.stop() } }
    }
}
