import XCTest

final class WalletUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }
    func testCaptureGuideInstructionsProgressAndCorrection() {
        let app = XCUIApplication(); app.launchArguments = ["--capture-guide-preview"]; app.launch()
        XCTAssertTrue(app.staticTexts["capture.instruction"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Titta rakt mot kameran")
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "0 av 3 bilder tagna")
        app.buttons["capture.preview.next"].tap()
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Vrid huvudet lite åt sidan")
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "1 av 3 bilder tagna")
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-capture-guide"; image.lifetime = .keepAlways; add(image)
        app.buttons["capture.preview.missing"].tap()
        XCTAssertEqual(app.staticTexts["capture.hint"].label, "Placera ansiktet i ovalen")
        XCTAssertEqual(app.otherElements["capture.ring"].value as? String, "1 av 3 bilder tagna")
        app.buttons["capture.preview.next"].tap()
        XCTAssertEqual(app.staticTexts["capture.instruction"].label, "Vrid åt andra hållet")
        XCTAssertFalse(app.staticTexts["Verifierad"].exists)
        XCTAssertFalse(app.buttons["Godkänn"].exists)
    }
    func testHomeAndScreenshot() {
        let app = XCUIApplication(); app.launch()
        XCTAssertTrue(app.staticTexts["home.heading"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["home.unlock"].exists)
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-home"; image.lifetime = .keepAlways; add(image)
    }
    func testAllTabsShowSafeLockedStates() {
        let app = XCUIApplication(); app.launch()
        app.tabBars.buttons["Legitimera"].tap()
        XCTAssertTrue(app.staticTexts["Lås upp för att se dina begäranden."].exists)
        XCTAssertFalse(app.buttons["Godkänn"].exists)
        app.tabBars.buttons["Aktivitet"].tap()
        XCTAssertTrue(app.staticTexts["Din aktivitet"].exists)
        app.tabBars.buttons["Inställningar"].tap()
        XCTAssertTrue(app.buttons["Lås upp openID"].exists)
        XCTAssertFalse(app.buttons["Spärra mitt ID"].exists)
    }
    func testGuideIsReachableWithoutBiometricPermission() {
        let app = XCUIApplication(); app.launch()
        app.swipeUp()
        app.buttons["home.guide"].tap()
        XCTAssertTrue(app.navigationBars["Så fungerar det"].waitForExistence(timeout: 3))
        app.buttons["Klart"].tap()
        XCTAssertTrue(app.buttons["home.unlock"].exists)
    }
    func testPrivacyIsAvailableWhileLocked() {
        let app = XCUIApplication(); app.launch()
        app.tabBars.buttons["Inställningar"].tap()
        app.buttons["Personuppgifter och säkerhet"].tap()
        XCTAssertTrue(app.navigationBars["Integritet"].waitForExistence(timeout: 3))
        XCTAssertFalse(app.buttons["Återaktivera"].exists)
    }
}
