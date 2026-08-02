import CoreGraphics
import Darwin
import Foundation
import ImageIO

private let requiredSize = 1024
private let requiredMargin = 64
private let visibleAlphaThreshold: UInt8 = 4

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(1)
}

guard CommandLine.arguments.count == 2 else {
    fail("usage: validate-app-icon <AppIcon.png>")
}

let path = CommandLine.arguments[1]
let url = URL(fileURLWithPath: path)
guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
else {
    fail("could not decode app icon: \(path)")
}

guard image.width == requiredSize, image.height == requiredSize else {
    fail("app icon must be \(requiredSize)x\(requiredSize); got \(image.width)x\(image.height)")
}

let bytesPerRow = image.width * 4
var pixels = [UInt8](repeating: 0, count: bytesPerRow * image.height)
let rendered = pixels.withUnsafeMutableBytes { bytes -> Bool in
    guard let context = CGContext(
        data: bytes.baseAddress,
        width: image.width,
        height: image.height,
        bitsPerComponent: 8,
        bytesPerRow: bytesPerRow,
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            | CGBitmapInfo.byteOrder32Big.rawValue
    ) else {
        return false
    }
    context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
    return true
}
guard rendered else {
    fail("could not render app icon pixels: \(path)")
}

var minX = image.width
var minY = image.height
var maxX = -1
var maxY = -1
for y in 0..<image.height {
    for x in 0..<image.width {
        let alpha = pixels[y * bytesPerRow + x * 4 + 3]
        if alpha >= visibleAlphaThreshold {
            minX = min(minX, x)
            minY = min(minY, y)
            maxX = max(maxX, x)
            maxY = max(maxY, y)
        }
    }
}

guard maxX >= minX, maxY >= minY else {
    fail("app icon contains no visible pixels: \(path)")
}

let margins = [minX, minY, image.width - 1 - maxX, image.height - 1 - maxY]
guard margins.allSatisfy({ $0 >= requiredMargin }) else {
    fail(
        "app icon needs at least \(requiredMargin) px transparent safe margin; "
            + "got left/top/right/bottom \(margins.map(String.init).joined(separator: "/"))"
    )
}
