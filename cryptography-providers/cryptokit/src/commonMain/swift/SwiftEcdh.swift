import CryptoKit
import Foundation

@objc public class SwiftEcdhPublicKey: NSObject {
    internal let key: Any
    private let curve: SwiftEcCurve

    internal init(key: Any, curve: SwiftEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func decodeRaw(
        curve: SwiftEcCurve,
        rawRepresentation: NSData
    )
        throws -> SwiftEcdhPublicKey
    {
        switch curve {
        case .p256:
            return SwiftEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdhPublicKey(
                key: try P521.KeyAgreement.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: SwiftEcCurve,
        derRepresentation: NSData
    ) throws -> SwiftEcdhPublicKey {
        switch curve {
        case .p256:
            return SwiftEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdhPublicKey(
                key: try P521.KeyAgreement.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: SwiftEcCurve,
        pemRepresentation: String
    ) throws -> SwiftEcdhPublicKey {
        switch curve {
        case .p256:
            return SwiftEcdhPublicKey(
                key: try P256.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return SwiftEcdhPublicKey(
                key: try P384.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return SwiftEcdhPublicKey(
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

    @objc public var curveType: SwiftEcCurve { curve }
}

@objc public class SwiftEcdhPrivateKey: NSObject {
    private let key: Any
    private let curve: SwiftEcCurve

    private init(key: Any, curve: SwiftEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func generate(curve: SwiftEcCurve) -> SwiftEcdhPrivateKey {
        switch curve {
        case .p256: return SwiftEcdhPrivateKey(key: P256.KeyAgreement.PrivateKey(), curve: .p256)
        case .p384: return SwiftEcdhPrivateKey(key: P384.KeyAgreement.PrivateKey(), curve: .p384)
        case .p521: return SwiftEcdhPrivateKey(key: P521.KeyAgreement.PrivateKey(), curve: .p521)
        }
    }

    @objc public static func decodeRaw(
        curve: SwiftEcCurve,
        rawRepresentation: NSData
    )
        throws -> SwiftEcdhPrivateKey
    {
        switch curve {
        case .p256:
            return SwiftEcdhPrivateKey(
                key: try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdhPrivateKey(
                key: try P384.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdhPrivateKey(
                key: try P521.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: SwiftEcCurve,
        derRepresentation: NSData
    ) throws -> SwiftEcdhPrivateKey {
        switch curve {
        case .p256:
            return SwiftEcdhPrivateKey(
                key: try P256.KeyAgreement.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdhPrivateKey(
                key: try P384.KeyAgreement.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdhPrivateKey(
                key: try P521.KeyAgreement.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: SwiftEcCurve,
        pemRepresentation: String
    ) throws -> SwiftEcdhPrivateKey {
        switch curve {
        case .p256:
            return SwiftEcdhPrivateKey(
                key: try P256.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return SwiftEcdhPrivateKey(
                key: try P384.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return SwiftEcdhPrivateKey(
                key: try P521.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func deriveSecret(publicKey: SwiftEcdhPublicKey) throws -> Data {
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

    @objc public func publicKey() -> SwiftEcdhPublicKey {
        return switch curve {
        case .p256:
            SwiftEcdhPublicKey(key: (key as! P256.KeyAgreement.PrivateKey).publicKey, curve: .p256)
        case .p384:
            SwiftEcdhPublicKey(key: (key as! P384.KeyAgreement.PrivateKey).publicKey, curve: .p384)
        case .p521:
            SwiftEcdhPublicKey(key: (key as! P521.KeyAgreement.PrivateKey).publicKey, curve: .p521)
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

    @objc public var curveType: SwiftEcCurve { curve }
}
