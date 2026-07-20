#!/usr/bin/env swift

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 6 else {
    fputs("usage: render-icon-variants.swift <source.png> <dark.png> <mono.png> <mark.png> <dot.png>\n", stderr)
    exit(2)
}

let sourceURL = URL(fileURLWithPath: CommandLine.arguments[1])
let darkURL = URL(fileURLWithPath: CommandLine.arguments[2])
let monoURL = URL(fileURLWithPath: CommandLine.arguments[3])
let markURL = URL(fileURLWithPath: CommandLine.arguments[4])
let dotURL = URL(fileURLWithPath: CommandLine.arguments[5])
let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
let bitmapInfo = CGBitmapInfo.byteOrder32Big.rawValue | CGImageAlphaInfo.premultipliedLast.rawValue

guard let imageSource = CGImageSourceCreateWithURL(sourceURL as CFURL, nil),
      let source = CGImageSourceCreateImageAtIndex(imageSource, 0, nil),
      source.width == 1024,
      source.height == 1024 else {
    fputs("source icon must be a readable 1024x1024 PNG\n", stderr)
    exit(1)
}

let width = source.width
let height = source.height
let bytesPerRow = width * 4
var sourcePixels = [UInt8](repeating: 0, count: bytesPerRow * height)

guard let context = CGContext(
    data: &sourcePixels,
    width: width,
    height: height,
    bitsPerComponent: 8,
    bytesPerRow: bytesPerRow,
    space: colorSpace,
    bitmapInfo: bitmapInfo
) else {
    fputs("could not create icon bitmap context\n", stderr)
    exit(1)
}
context.draw(source, in: CGRect(x: 0, y: 0, width: width, height: height))

func isAmber(_ red: Double, _ green: Double, _ blue: Double) -> Bool {
    red > 0.65 && red > blue + 0.08 && green > blue + 0.03
}

func write(_ output: [UInt8], to destination: URL) throws {
    let data = Data(output)
    guard let provider = CGDataProvider(data: data as CFData),
          let rendered = CGImage(
            width: width,
            height: height,
            bitsPerComponent: 8,
            bitsPerPixel: 32,
            bytesPerRow: bytesPerRow,
            space: colorSpace,
            bitmapInfo: CGBitmapInfo(rawValue: bitmapInfo),
            provider: provider,
            decode: nil,
            shouldInterpolate: true,
            intent: .defaultIntent
          ),
          let destinationWriter = CGImageDestinationCreateWithURL(
            destination as CFURL,
            UTType.png.identifier as CFString,
            1,
            nil
          ) else {
        throw CocoaError(.fileWriteUnknown)
    }

    CGImageDestinationAddImage(destinationWriter, rendered, nil)
    guard CGImageDestinationFinalize(destinationWriter) else {
        throw CocoaError(.fileWriteUnknown)
    }
}

func render(
    to destination: URL,
    transform: (Double, Double, Double) -> (Double, Double, Double)
) throws {
    var output = sourcePixels

    for index in stride(from: 0, to: output.count, by: 4) {
        let alpha = Double(sourcePixels[index + 3]) / 255
        guard alpha > 0 else { continue }

        let red = min(1, Double(sourcePixels[index]) / 255 / alpha)
        let green = min(1, Double(sourcePixels[index + 1]) / 255 / alpha)
        let blue = min(1, Double(sourcePixels[index + 2]) / 255 / alpha)
        let transformed = transform(red, green, blue)

        output[index] = UInt8((min(1, max(0, transformed.0)) * alpha * 255).rounded())
        output[index + 1] = UInt8((min(1, max(0, transformed.1)) * alpha * 255).rounded())
        output[index + 2] = UInt8((min(1, max(0, transformed.2)) * alpha * 255).rounded())
    }

    try write(output, to: destination)
}

func renderMask(to destination: URL, alphaFor: (Double, Double, Double) -> Double) throws {
    var output = [UInt8](repeating: 0, count: sourcePixels.count)

    for index in stride(from: 0, to: output.count, by: 4) {
        let sourceAlpha = Double(sourcePixels[index + 3]) / 255
        guard sourceAlpha > 0 else { continue }

        let red = min(1, Double(sourcePixels[index]) / 255 / sourceAlpha)
        let green = min(1, Double(sourcePixels[index + 1]) / 255 / sourceAlpha)
        let blue = min(1, Double(sourcePixels[index + 2]) / 255 / sourceAlpha)
        let alpha = min(1, max(0, alphaFor(red, green, blue))) * sourceAlpha
        let value = UInt8((alpha * 255).rounded())
        output[index] = value
        output[index + 1] = value
        output[index + 2] = value
        output[index + 3] = value
    }

    try write(output, to: destination)
}

do {
    try render(to: darkURL) { red, green, blue in
        if isAmber(red, green, blue) {
            return (red, green, blue)
        }
        let luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue
        let inverted = min(0.90, max(0.14, 0.14 + (1 - luminance) * 0.82))
        return (min(1, inverted * 1.015), inverted, inverted * 0.985)
    }

    try render(to: monoURL) { red, green, blue in
        let luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue
        let neutral = isAmber(red, green, blue) ? 0.58 : luminance
        return (neutral, neutral, neutral)
    }

    try renderMask(to: markURL) { red, green, blue in
        guard !isAmber(red, green, blue) else { return 0 }
        let luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue
        return (0.78 - luminance) / 0.55
    }

    try renderMask(to: dotURL) { red, green, blue in
        guard isAmber(red, green, blue) else { return 0 }
        let redChroma = (red - blue - 0.05) / 0.25
        let greenChroma = (green - blue) / 0.25
        return min(redChroma, greenChroma)
    }
} catch {
    fputs("failed to render icon variants: \(error.localizedDescription)\n", stderr)
    exit(1)
}
