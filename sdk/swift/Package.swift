// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OpenProof",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "OpenProof", targets: ["OpenProof"]),
    ],
    targets: [
        .target(name: "OpenProof"),
    ]
)
