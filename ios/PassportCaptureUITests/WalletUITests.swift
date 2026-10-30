import XCTest

final class WalletUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }
    func testFailedStatusOffersRegistrationButRequiresCurrentNotice() {
        let app = XCUIApplication(); app.launchArguments = ["--recovery-preview"]; app.launch()
        let resume = app.buttons["home.resumeRegistration"]
        XCTAssertTrue(resume.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["home.statusMessage"].exists)
        for _ in 0..<5 { if resume.isHittable { break }; app.swipeUp() }
        resume.tap()
        XCTAssertTrue(app.buttons["Hämta information inför registrering"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.textFields["enrollment.number"].exists)
        app.buttons["Stäng"].firstMatch.tap()
        XCTAssertTrue(resume.waitForExistence(timeout: 5))
    }
    func testExpiredKeyMustBeRevokedBeforeRemoval() {
        let app = XCUIApplication(); app.launchArguments = ["--recovery-preview", "--EXPIRED"]; app.launch()
        app.buttons["Inställningar"].tap()
        for _ in 0..<3 { app.swipeUp() }
        XCTAssertTrue(app.buttons["Spärra mitt ID"].exists)
        XCTAssertFalse(app.buttons["settings.forgetCredential"].exists)
        XCTAssertFalse(app.buttons["home.resumeRegistration"].exists)
    }
    func testConfirmedRevocationAndRemovalReturnToRegistration() {
        let app = XCUIApplication(); app.launchArguments = ["--recovery-preview", "--confirmed-revocation"]; app.launch()
        app.buttons["Inställningar"].tap()
        let forget = app.buttons["settings.forgetCredential"]
        for _ in 0..<5 { if forget.isHittable { break }; app.swipeUp() }
        XCTAssertTrue(forget.isHittable); forget.tap()
        app.buttons["Ta bort nyckeln"].tap()
        XCTAssertTrue(app.buttons["home.register"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["home.register"].isEnabled)
        XCTAssertFalse(app.staticTexts["home.statusMessage"].exists)
    }
    func testRejectIsVisibleWithoutScrollingForEveryRequestKind() {
        for variant in [[], ["--pin"], ["--sign"], ["--sign", "--pin"], ["--sign", "--pin", "--largest-text"]] as [[String]] {
            let app = XCUIApplication(); app.launchArguments = ["--approval-preview"] + variant; app.launch()
            let reject = app.buttons[variant.contains("--sign") ? "Avböj underskrift" : "Neka begäran"]
            XCTAssertTrue(reject.waitForExistence(timeout: 5))
            // Accessibility can expose the button before the simulator draws its first frame.
            // Wait for interaction readiness without scrolling or changing the request.
            let ready = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == true AND hittable == true"), object: reject)
            let result = XCTWaiter.wait(for: [ready], timeout: 10)
            if result != .completed {
                let screenshot = XCTAttachment(screenshot: app.screenshot())
                screenshot.name = "Approval refusal readiness failure"; screenshot.lifetime = .keepAlways; add(screenshot)
                let hierarchy = XCTAttachment(string: app.debugDescription)
                hierarchy.name = "Approval refusal hierarchy"; hierarchy.lifetime = .keepAlways; add(hierarchy)
            }
            XCTAssertEqual(result, .completed, "Reject must be visible before scrolling: \(variant)")
            XCTAssertTrue(reject.isEnabled)
            XCTAssertGreaterThanOrEqual(reject.frame.minY, app.frame.minY)
            XCTAssertLessThanOrEqual(reject.frame.maxY, app.frame.maxY)
            app.terminate()
        }
    }
    func testRejectRemainsVisibleWithKeyboardAndDoesNotRequireSecurityCode() {
        let app = XCUIApplication(); app.launchArguments = ["--approval-preview", "--pin"]; app.launch()
        let field = app.secureTextFields["approval.securityCode"]
        for _ in 0..<6 { if field.isHittable { break }; app.swipeUp() }
        XCTAssertTrue(field.isHittable); field.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["approval.approve"].isEnabled)
        let reject = app.buttons["Neka begäran"]
        XCTAssertTrue(reject.isHittable)
        XCTAssertTrue(reject.isEnabled)
        XCTAssertLessThanOrEqual(reject.frame.maxY, app.keyboards.firstMatch.frame.minY)
    }
    func testExpiredRequestKeepsBothDecisionsDisabled() {
        let app = XCUIApplication(); app.launchArguments = ["--approval-preview", "--expired"]; app.launch()
        let reject = app.buttons["Neka begäran"]
        XCTAssertTrue(reject.waitForExistence(timeout: 5))
        XCTAssertFalse(reject.isEnabled)
        XCTAssertFalse(app.buttons["approval.approve"].isEnabled)
    }
    func testCaptureGuideInstructionsProgressAndCorrection() {
        let app = XCUIApplication(); app.launchArguments = ["--capture-guide-preview"]; app.launch()
        XCTAssertTrue(app.staticTexts["capture.instruction"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Titta rakt mot kameran")
        XCTAssertTrue(app.staticTexts["capture.instruction"].isHittable)
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "0 av 3 bilder tagna")
        app.buttons["capture.preview.next"].tap()
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Vrid huvudet lite åt höger")
        XCTAssertTrue(app.staticTexts["capture.instruction"].isHittable)
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "1 av 3 bilder tagna")
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-capture-guide"; image.lifetime = .keepAlways; add(image)
        app.buttons["capture.preview.missing"].tap()
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Placera ansiktet i ovalen")
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "1 av 3 bilder tagna")
        app.buttons["capture.preview.next"].tap()
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Vrid huvudet lite åt vänster")
        XCTAssertFalse(app.staticTexts["Verifierad"].exists)
        XCTAssertFalse(app.buttons["Godkänn"].exists)
    }
    func testPassportGuideInstructionAndSyntheticPreview() {
        let app = XCUIApplication(); app.launchArguments = ["--passport-guide-preview"]; app.launch()
        let instruction = app.staticTexts["passport.instruction"]
        XCTAssertTrue(instruction.waitForExistence(timeout: 5))
        XCTAssertTrue(instruction.isHittable)
        XCTAssertLessThanOrEqual(instruction.frame.maxX, app.frame.maxX)
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-passport-guide"; image.lifetime = .keepAlways; add(image)
        XCTAssertFalse(app.staticTexts["Verifierad"].exists)
    }
    func testControlCodePreservesLeadingZeroAtLargestTextSize() {
        let app = XCUIApplication(); app.launchArguments = ["--usability-preview"]; app.launch()
        app.buttons["Kontrollkod med stor text"].tap()
        let code = app.descendants(matching: .any)["approval.code"].firstMatch
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        XCTAssertEqual(code.value as? String, "0, 1, 2, 3, 4, 5")
        XCTAssertGreaterThanOrEqual(code.frame.minX, 0)
        XCTAssertLessThanOrEqual(code.frame.maxX, app.frame.maxX)
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-large-control-code"; image.lifetime = .keepAlways; add(image)
    }
    func testLargestTextCameraInstructionIsOutsidePreviewAndReadable() {
        let app = XCUIApplication(); app.launchArguments = ["--usability-preview"]; app.launch()
        app.buttons["Kameraguide med stor text"].tap()
        let instruction = app.staticTexts["capture.instruction"]
        for _ in 0..<5 { if instruction.isHittable { break }; app.swipeUp() }
        XCTAssertTrue(instruction.isHittable)
        XCTAssertEqual(instruction.label, "Vrid huvudet lite åt höger")
        XCTAssertLessThanOrEqual(instruction.frame.maxX, app.frame.maxX)
    }
    func testPassportFieldsKeepLabelsAndExplainMissingDate() {
        let app = XCUIApplication(); app.launchArguments = ["--usability-preview"]; app.launch()
        app.buttons["Passformulär"].tap()
        XCTAssertFalse(app.textFields["enrollment.number"].exists)
        let terms = app.switches["enrollment.terms"]
        for _ in 0..<6 { if terms.isHittable { break }; app.swipeUp() }
        terms.tap()
        XCTAssertEqual(terms.value as? String, "1", app.debugDescription)
        XCTAssertFalse(app.textFields["enrollment.number"].exists)
        let biometrics = app.switches["enrollment.biometrics"]
        for _ in 0..<6 { if biometrics.isHittable { break }; app.swipeUp() }
        biometrics.tap()
        XCTAssertEqual(biometrics.value as? String, "1", app.debugDescription)
        let number = app.textFields["enrollment.number"]
        for _ in 0..<5 { if number.isHittable { break }; app.swipeUp() }
        number.tap(); number.typeText("ABC123")
        XCTAssertTrue(app.staticTexts["Passnummer"].exists)
        app.buttons["Klart"].tap()
        let preparation = app.buttons["Förbered dig innan du börjar"]
        for _ in 0..<5 { if preparation.isHittable { break }; app.swipeDown() }
        preparation.tap()
        let practice = app.buttons["enrollment.cameraPractice"]
        for _ in 0..<5 { if practice.isHittable { break }; app.swipeUp() }
        XCTAssertTrue(practice.isHittable)
        // Expansion moves this button past the scanner button's old position.
        // Wait for its actual frame to settle before generating a coordinate tap.
        var previousFrame = CGRect.zero
        var stableSince = Date()
        let settled = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            let frame = practice.frame
            guard practice.isHittable else { return false }
            if frame != previousFrame { previousFrame = frame; stableSince = Date(); return false }
            return Date().timeIntervalSince(stableSince) >= 0.5
        }, object: practice)
        XCTAssertEqual(XCTWaiter.wait(for: [settled], timeout: 5), .completed)
        practice.tap()
        XCTAssertTrue(app.buttons["Stäng kameraprovet"].waitForExistence(timeout: 3))
        app.buttons["Stäng kameraprovet"].tap()
        XCTAssertEqual(number.value as? String, "ABC123")
        XCTAssertFalse(app.descendants(matching: .any)["enrollment.inputIssue"].firstMatch.exists)
        let read = app.buttons["enrollment.read"]
        for _ in 0..<5 { if read.isHittable { break }; app.swipeUp() }
        read.tap()
        XCTAssertTrue(app.descendants(matching: .any)["enrollment.inputIssue"].firstMatch.waitForExistence(timeout: 3))
        XCTAssertFalse(app.staticTexts["Ansluter säkert"].exists)
    }
    func testHomeAndScreenshot() {
        let app = XCUIApplication(); app.launchArguments = []; app.launch()
        XCTAssertTrue(app.staticTexts["home.heading"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["home.unlock"].exists)
        let betaHours = app.staticTexts["home.betaHours"].label
        XCTAssertTrue(betaHours.contains("dygnet runt till och med 30 november 2026"))
        XCTAssertTrue(betaHours.contains("1 december kl. 00.00 svensk tid"))
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-home"; image.lifetime = .keepAlways; add(image)
    }
    func testAllTabsShowSafeLockedStates() {
        let app = XCUIApplication(); app.launchArguments = []; app.launch()
        XCTAssertTrue(app.staticTexts["home.heading"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["Legitimera"].waitForExistence(timeout: 5))
        app.buttons["Legitimera"].tap()
        XCTAssertTrue(app.staticTexts["Lås upp för att se dina begäranden."].exists)
        XCTAssertFalse(app.buttons["Godkänn"].exists)
        app.buttons["Aktivitet"].tap()
        XCTAssertTrue(app.staticTexts["Din aktivitet"].exists)
        XCTAssertTrue(app.buttons["Inställningar"].waitForExistence(timeout: 5))
        app.buttons["Inställningar"].tap()
        XCTAssertTrue(app.buttons["Lås upp openID"].exists)
        XCTAssertFalse(app.buttons["Spärra mitt ID"].exists)
    }
    func testInstalledBuildCanBeIdentifiedWithoutUnlocking() {
        let app = XCUIApplication(); app.launchArguments = []; app.launch()
        app.buttons["Inställningar"].tap()
        let version = app.descendants(matching: .any)["settings.version"].firstMatch
        for _ in 0..<4 { if version.isHittable { break }; app.swipeUp() }
        XCTAssertTrue(version.isHittable)
        XCTAssertNotNil((version.value as? String)?.range(of: #"^[0-9]+\.[0-9]+\.[0-9]+ \([0-9]+\)$"#, options: .regularExpression))
    }
    func testGuideIsReachableWithoutBiometricPermission() {
        let app = XCUIApplication(); app.launchArguments = []; app.launch()
        app.swipeUp()
        app.buttons["home.guide"].tap()
        XCTAssertTrue(app.navigationBars["Så fungerar det"].waitForExistence(timeout: 3))
        app.buttons["Klart"].tap()
        XCTAssertTrue(app.buttons["home.unlock"].exists)
    }
    func testPrivacyIsAvailableWhileLocked() {
        let app = XCUIApplication(); app.launchArguments = []; app.launch()
        XCTAssertTrue(app.buttons["Inställningar"].waitForExistence(timeout: 5))
        app.buttons["Inställningar"].tap()
        app.buttons["Personuppgifter och säkerhet"].tap()
        XCTAssertTrue(app.navigationBars["Integritet"].waitForExistence(timeout: 3))
        XCTAssertFalse(app.buttons["Återaktivera"].exists)
    }
}
