import Foundation
import AVFoundation
import ImageIO
import UniformTypeIdentifiers

let asset = AVURLAsset(url: URL(fileURLWithPath: CommandLine.arguments[1]))
let generator = AVAssetImageGenerator(asset: asset)
generator.appliesPreferredTrackTransform = true
let duration = CMTimeGetSeconds(asset.duration)
let tracks = asset.tracks(withMediaType: .video)
guard abs(duration - 105) < 0.1, let track = tracks.first else { fatalError("Unexpected movie") }
for second in [0, 50, 87, 104] {
    let cg = try generator.copyCGImage(at: CMTime(value: Int64(second), timescale: 1), actualTime: nil)
    let dest = URL(fileURLWithPath: CommandLine.arguments[2]).appendingPathComponent("decoded-\(second).png")
    let output = CGImageDestinationCreateWithURL(dest as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(output, cg, nil)
    guard CGImageDestinationFinalize(output) else { fatalError("Cannot write decoded image") }
}
print("PASS: duration=\(duration)s resolution=\(track.naturalSize) video_tracks=\(tracks.count); decoded 0/50/87/104 seconds")
