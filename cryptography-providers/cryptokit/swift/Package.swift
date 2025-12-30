// swift-tools-version:6.2
import PackageDescription

// dwc = dev.whyoleg.cryptography
let package = Package(
    name: "DwcCryptoKitInterop",
    // versions for CryptoKit and/or Kotlin/Native support
    platforms: [
        .macOS(.v11),
        .iOS(.v14),
        .tvOS(.v14),
        .watchOS(.v7)
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
