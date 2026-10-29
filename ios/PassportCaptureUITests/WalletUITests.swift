import XCTest

final class WalletUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }
    func testRejectIsVisibleWithoutScrollingForEveryRequestKind() {
        for variant in [[], ["--pin"], ["--sign"], ["--sign", "--pin"], ["--sign", "--pin", "--largest-text"]] as [[String]] {
            let app = XCUIApplication(); app.launchArguments = ["--approval-preview"] + variant; app.launch()
            let reject = app.buttons[variant.contains("--sign") ? "Avböj underskrift" : "Neka begäran"]
            XCTAssertTrue(reject.waitForExistence(timeout: 5))
            XCTAssertTrue(reject.isHittable, "Reject must be visible before scrolling: \(variant)")
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
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "0 av 3 bilder tagna")
        app.buttons["capture.preview.next"].tap()
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Vrid huvudet lite åt höger")
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
        let number = app.textFields["enrollment.number"]
        for _ in 0..<5 { if number.isHittable { break }; app.swipeUp() }
        number.tap(); number.typeText("ABC123")
        XCTAssertTrue(app.staticTexts["Passnummer"].exists)
        app.buttons["Klart"].tap()
        let preparation = app.buttons["enrollment.prepare"]
        for _ in 0..<5 { if preparation.isHittable { break }; app.swipeDown() }
        preparation.tap()
        let practice = app.buttons["Prova kameran först – utan att skicka bilder"]
        for _ in 0..<5 { if practice.isHittable { break }; app.swipeUp() }
        practice.tap()
        XCTAssertTrue(app.buttons["Stäng kameraprovet"].waitForExistence(timeout: 3))
        app.buttons["Stäng kameraprovet"].tap()
        XCTAssertEqual(number.value as? String, "ABC123")
        XCTAssertFalse(app.descendants(matching: .any)["enrollment.inputIssue"].firstMatch.exists)
        let consent = app.switches.firstMatch
        for _ in 0..<6 { if consent.isHittable { break }; app.swipeUp() }
        consent.tap()
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
