// macOS: swift tools/media/encode_video.swift manifest.json output.mp4
// Encode actual screenshot-based demonstration frames with AVFoundation.
import Foundation
import AVFoundation
import CoreGraphics
import ImageIO

struct Scene: Decodable { let path: String; let seconds: Int }
let args = CommandLine.arguments
guard args.count == 3 else { fatalError("Usage: encode_video manifest.json output.mp4") }
let scenes = try JSONDecoder().decode([Scene].self, from: Data(contentsOf: URL(fileURLWithPath: args[1])))
let output = URL(fileURLWithPath: args[2])
let width = 1920, height = 1080, fps: Int32 = 2
let writer = try AVAssetWriter(outputURL: output, fileType: .mp4)
let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
    AVVideoCodecKey: AVVideoCodecType.h264,
    AVVideoWidthKey: width, AVVideoHeightKey: height,
    AVVideoCompressionPropertiesKey: [AVVideoAverageBitRateKey: 2_500_000, AVVideoMaxKeyFrameIntervalKey: 20]
])
input.expectsMediaDataInRealTime = false
let attrs: [String: Any] = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32ARGB,
                          kCVPixelBufferWidthKey as String: width, kCVPixelBufferHeightKey as String: height,
                          kCVPixelBufferCGImageCompatibilityKey as String: true,
                          kCVPixelBufferCGBitmapContextCompatibilityKey as String: true]
let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: attrs)
writer.add(input)
guard writer.startWriting() else { fatalError("startWriting: \(String(describing: writer.error))") }
writer.startSession(atSourceTime: .zero)
var frame: Int64 = 0
for scene in scenes {
    guard let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: scene.path) as CFURL, nil),
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { fatalError("Cannot read frame") }
    var pixelBuffer: CVPixelBuffer?
    CVPixelBufferCreate(kCFAllocatorDefault, width, height, kCVPixelFormatType_32ARGB, attrs as CFDictionary, &pixelBuffer)
    guard let buffer = pixelBuffer else { fatalError("No pixel buffer") }
    CVPixelBufferLockBaseAddress(buffer, [])
    let context = CGContext(data: CVPixelBufferGetBaseAddress(buffer), width: width, height: height,
                            bitsPerComponent: 8, bytesPerRow: CVPixelBufferGetBytesPerRow(buffer),
                            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue)!
    context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
    CVPixelBufferUnlockBaseAddress(buffer, [])
    for _ in 0..<(scene.seconds * Int(fps)) {
        let deadline = Date().addingTimeInterval(20)
        while !input.isReadyForMoreMediaData {
            if writer.status == .failed || Date() > deadline { fatalError("Encoder stalled: \(String(describing: writer.error))") }
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard adaptor.append(buffer, withPresentationTime: CMTime(value: frame, timescale: fps)) else {
            fatalError("Append failed: \(String(describing: writer.error))")
        }
        frame += 1
    }
}
writer.endSession(atSourceTime: CMTime(value: frame, timescale: fps))
input.markAsFinished()
let semaphore = DispatchSemaphore(value: 0)
writer.finishWriting { semaphore.signal() }
guard semaphore.wait(timeout: .now() + 60) == .success, writer.status == .completed else {
    fatalError("Finish failed: \(String(describing: writer.error))")
}
print("Saved \(output.path), \(frame) frames, \(Double(frame)/Double(fps)) seconds")
