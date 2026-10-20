import XCTest

final class WalletUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }
    func testHomeAndRealSimulatorScreenshot() {
        let app = XCUIApplication(); app.launch()
        XCTAssertTrue(app.staticTexts["home.heading"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["home.unlock"].exists)
        let image = XCTAttachment(screenshot: app.screenshot()); image.name = "openID-home"; image.lifetime = .keepAlways; add(image)
    }
    func testAllTabsShowSafeLockedStates() {
        let app = XCUIApplication(); app.launch()
        app.tabBars.buttons["Legitimera"].tap()
        XCTAssertTrue(app.staticTexts["Lås upp för att legitimera dig"].exists)
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
    func testPrivacyAndRecoveryDoNotInventAnIdentity() {
        let app = XCUIApplication(); app.launch()
        app.tabBars.buttons["Inställningar"].tap()
        app.buttons["Personuppgifter och säkerhet"].tap()
        XCTAssertTrue(app.navigationBars["Integritet"].waitForExistence(timeout: 3))
        XCTAssertFalse(app.buttons["Återaktivera"].exists)
    }
}
