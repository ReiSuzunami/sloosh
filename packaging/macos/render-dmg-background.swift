#!/usr/bin/env swift

import AppKit
import Foundation

let width: CGFloat = 720
let height: CGFloat = 440
let scale: CGFloat = 2

guard CommandLine.arguments.count == 2 else {
    fputs("usage: render-dmg-background.swift <output.png>\n", stderr)
    exit(2)
}

guard let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(width * scale),
    pixelsHigh: Int(height * scale),
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
) else {
    fputs("could not create background bitmap\n", stderr)
    exit(1)
}
bitmap.size = NSSize(width: width, height: height)

NSGraphicsContext.saveGraphicsState()
guard let graphics = NSGraphicsContext(bitmapImageRep: bitmap) else {
    fputs("could not create background graphics context\n", stderr)
    exit(1)
}
NSGraphicsContext.current = graphics

NSColor(
    calibratedRed: 0.965,
    green: 0.969,
    blue: 0.976,
    alpha: 1
).setFill()
NSRect(x: 0, y: 0, width: width, height: height).fill()

graphics.flushGraphics()
NSGraphicsContext.restoreGraphicsState()

guard let png = bitmap.representation(using: .png, properties: [:]) else {
    fputs("could not encode background PNG\n", stderr)
    exit(1)
}

do {
    try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]), options: .atomic)
} catch {
    fputs("could not write background PNG: \(error)\n", stderr)
    exit(1)
}
