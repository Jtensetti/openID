import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

// Package the supplied symbols at Apple's required icon size, without redrawing or recoloring.
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let assets = root.appendingPathComponent("PassportCapture/Assets.xcassets")
for color in ["hav", "skog", "aprikos", "lera", "sol", "lavendel", "ros", "grafit"] {
    let source = assets.appendingPathComponent("TjippSymbol-\(color).imageset/image.png")
    guard let input = CGImageSourceCreateWithURL(source as CFURL, nil),
          let image = CGImageSourceCreateImageAtIndex(input, 0, nil),
          let context = CGContext(data: nil, width: 1024, height: 1024, bitsPerComponent: 8, bytesPerRow: 4096,
                                  space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
    else { fatalError("Cannot package original symbol: \(source.path)") }
    context.setFillColor(CGColor(red: 250.0/255, green: 248.0/255, blue: 242.0/255, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: 1024, height: 1024))
    context.interpolationQuality = .high
    context.draw(image, in: CGRect(x: 112, y: 112, width: 800, height: 800))
    let name = color == "hav" ? "AppIcon" : "AppIcon-\(color)"
    let folder = assets.appendingPathComponent("\(name).appiconset")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    let output = CGImageDestinationCreateWithURL(folder.appendingPathComponent("AppIcon.png") as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(output, context.makeImage()!, nil)
    precondition(CGImageDestinationFinalize(output))
    let contents: [String: Any] = ["images": [["filename":"AppIcon.png", "idiom":"universal", "platform":"ios", "size":"1024x1024"]],
                                  "info": ["author":"xcode", "version":1]]
    try JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys]).write(to: folder.appendingPathComponent("Contents.json"))
}
