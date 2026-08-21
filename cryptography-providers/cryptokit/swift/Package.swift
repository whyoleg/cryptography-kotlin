// swift-tools-version:6.0
import PackageDescription

// dwc = dev.whyoleg.cryptography
let package = Package(
    name: "DwcCryptoKitInterop",
    // versions for CryptoKit and/or Kotlin/Native support
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "DwcCryptoKitInterop",
            type: .static,
            targets: ["DwcCryptoKitInterop"]
        )
    ],
    dependencies: [],
    targets: [
        .target(name: "DwcCryptoKitInterop")
    ]
)
