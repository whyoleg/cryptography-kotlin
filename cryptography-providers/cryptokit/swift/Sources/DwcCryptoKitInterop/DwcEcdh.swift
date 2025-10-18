import CryptoKit
import Foundation

@objc public class DwcEcdhPublicKey: NSObject {
    internal let key: Any
    private let curve: DwcEcCurve

    internal init(key: Any, curve: DwcEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func decodeRaw(
        curve: DwcEcCurve,
        rawRepresentation: NSData
    )
        throws -> DwcEcdhPublicKey
    {
        switch curve {
        case .p256:
            return DwcEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdhPublicKey(
                key: try P521.KeyAgreement.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeRawCompressed(
        curve: DwcEcCurve,
        compressedRepresentation: NSData
    )
        throws -> DwcEcdhPublicKey
    {
        guard #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) else {
            throw DwcCryptoKitError.unavailableOSVersion
        }
        switch curve {
        case .p256:
            return DwcEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(compressedRepresentation: compressedRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdhPublicKey(
                key: try P521.KeyAgreement.PublicKey(compressedRepresentation: compressedRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: DwcEcCurve,
        derRepresentation: NSData
    ) throws -> DwcEcdhPublicKey {
        switch curve {
        case .p256:
            return DwcEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdhPublicKey(
                key: try P521.KeyAgreement.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: DwcEcCurve,
        pemRepresentation: String
    ) throws -> DwcEcdhPublicKey {
        switch curve {
        case .p256:
            return DwcEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return DwcEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return DwcEcdhPublicKey(
                key: try P521.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func rawRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PublicKey).x963Representation
        case .p384: return (key as! P384.KeyAgreement.PublicKey).x963Representation
        case .p521: return (key as! P521.KeyAgreement.PublicKey).x963Representation
        }
    }

    @objc public func compressedRepresentation() throws -> Data {
        guard #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) else {
            throw DwcCryptoKitError.unavailableOSVersion
        }
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PublicKey).compressedRepresentation
        case .p384: return (key as! P384.KeyAgreement.PublicKey).compressedRepresentation
        case .p521: return (key as! P521.KeyAgreement.PublicKey).compressedRepresentation
        }
    }

    @objc public func derRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PublicKey).derRepresentation
        case .p384: return (key as! P384.KeyAgreement.PublicKey).derRepresentation
        case .p521: return (key as! P521.KeyAgreement.PublicKey).derRepresentation
        }
    }

    @objc public func pemRepresentation() -> String {
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PublicKey).pemRepresentation
        case .p384: return (key as! P384.KeyAgreement.PublicKey).pemRepresentation
        case .p521: return (key as! P521.KeyAgreement.PublicKey).pemRepresentation
        }
    }

    @objc public var curveType: DwcEcCurve { curve }
}

@objc public class DwcEcdhPrivateKey: NSObject {
    private let key: Any
    private let curve: DwcEcCurve

    private init(key: Any, curve: DwcEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func generate(curve: DwcEcCurve) -> DwcEcdhPrivateKey {
        switch curve {
        case .p256: return DwcEcdhPrivateKey(key: P256.KeyAgreement.PrivateKey(), curve: .p256)
        case .p384: return DwcEcdhPrivateKey(key: P384.KeyAgreement.PrivateKey(), curve: .p384)
        case .p521: return DwcEcdhPrivateKey(key: P521.KeyAgreement.PrivateKey(), curve: .p521)
        }
    }

    @objc public static func decodeRaw(
        curve: DwcEcCurve,
        rawRepresentation: NSData
    )
        throws -> DwcEcdhPrivateKey
    {
        switch curve {
        case .p256:
            return DwcEcdhPrivateKey(
                key: try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdhPrivateKey(
                key: try P384.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdhPrivateKey(
                key: try P521.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: DwcEcCurve,
        derRepresentation: NSData
    ) throws -> DwcEcdhPrivateKey {
        switch curve {
        case .p256:
            return DwcEcdhPrivateKey(
                key: try P256.KeyAgreement.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdhPrivateKey(
                key: try P384.KeyAgreement.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdhPrivateKey(
                key: try P521.KeyAgreement.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: DwcEcCurve,
        pemRepresentation: String
    ) throws -> DwcEcdhPrivateKey {
        switch curve {
        case .p256:
            return DwcEcdhPrivateKey(
                key: try P256.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return DwcEcdhPrivateKey(
                key: try P384.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return DwcEcdhPrivateKey(
                key: try P521.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func deriveSecret(publicKey: DwcEcdhPublicKey) throws -> Data {
        let secret =
            switch curve {
            case .p256:
                try (key as! P256.KeyAgreement.PrivateKey).sharedSecretFromKeyAgreement(
                    with: publicKey.key as! P256.KeyAgreement.PublicKey)
            case .p384:
                try (key as! P384.KeyAgreement.PrivateKey).sharedSecretFromKeyAgreement(
                    with: publicKey.key as! P384.KeyAgreement.PublicKey)
            case .p521:
                try (key as! P521.KeyAgreement.PrivateKey).sharedSecretFromKeyAgreement(
                    with: publicKey.key as! P521.KeyAgreement.PublicKey)
            }
        return secret.withUnsafeBytes { Data($0) }
    }

    @objc public func publicKey() -> DwcEcdhPublicKey {
        return switch curve {
        case .p256:
            DwcEcdhPublicKey(key: (key as! P256.KeyAgreement.PrivateKey).publicKey, curve: .p256)
        case .p384:
            DwcEcdhPublicKey(key: (key as! P384.KeyAgreement.PrivateKey).publicKey, curve: .p384)
        case .p521:
            DwcEcdhPublicKey(key: (key as! P521.KeyAgreement.PrivateKey).publicKey, curve: .p521)
        }
    }

    @objc public func rawRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PrivateKey).rawRepresentation
        case .p384: return (key as! P384.KeyAgreement.PrivateKey).rawRepresentation
        case .p521: return (key as! P521.KeyAgreement.PrivateKey).rawRepresentation
        }
    }

    @objc public func derRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PrivateKey).derRepresentation
        case .p384: return (key as! P384.KeyAgreement.PrivateKey).derRepresentation
        case .p521: return (key as! P521.KeyAgreement.PrivateKey).derRepresentation
        }
    }

    @objc public func pemRepresentation() -> String {
        switch curve {
        case .p256: return (key as! P256.KeyAgreement.PrivateKey).pemRepresentation
        case .p384: return (key as! P384.KeyAgreement.PrivateKey).pemRepresentation
        case .p521: return (key as! P521.KeyAgreement.PrivateKey).pemRepresentation
        }
    }

    @objc public var curveType: DwcEcCurve { curve }
}
