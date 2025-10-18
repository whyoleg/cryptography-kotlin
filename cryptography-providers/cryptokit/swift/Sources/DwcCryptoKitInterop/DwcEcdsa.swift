import CryptoKit
import Foundation

@objc public enum DwcEcCurve: Int {
    case p256, p384, p521
}

@objc public class DwcEcdsaPublicKey: NSObject {
    private let key: Any
    private let curve: DwcEcCurve

    internal init(key: Any, curve: DwcEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func decodeRaw(
        curve: DwcEcCurve,
        rawRepresentation: NSData
    )
        throws -> DwcEcdsaPublicKey
    {
        switch curve {
        case .p256:
            return DwcEcdsaPublicKey(
                key: try P256.Signing.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdsaPublicKey(
                key: try P384.Signing.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdsaPublicKey(
                key: try P521.Signing.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeRawCompressed(
        curve: DwcEcCurve,
        compressedRepresentation: NSData
    )
        throws -> DwcEcdsaPublicKey
    {
        guard #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) else {
            throw DwcCryptoKitError.unavailableOSVersion
        }
        switch curve {
        case .p256:
            return DwcEcdsaPublicKey(
                key: try P256.Signing.PublicKey(compressedRepresentation: compressedRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdsaPublicKey(
                key: try P384.Signing.PublicKey(compressedRepresentation: compressedRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdsaPublicKey(
                key: try P521.Signing.PublicKey(compressedRepresentation: compressedRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: DwcEcCurve,
        derRepresentation: NSData
    ) throws -> DwcEcdsaPublicKey {
        switch curve {
        case .p256:
            return DwcEcdsaPublicKey(
                key: try P256.Signing.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdsaPublicKey(
                key: try P384.Signing.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdsaPublicKey(
                key: try P521.Signing.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: DwcEcCurve,
        pemRepresentation: String
    ) throws -> DwcEcdsaPublicKey {
        switch curve {
        case .p256:
            return DwcEcdsaPublicKey(
                key: try P256.Signing.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return DwcEcdsaPublicKey(
                key: try P384.Signing.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return DwcEcdsaPublicKey(
                key: try P521.Signing.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func verifyDer(signature: NSData, digest: DwcDigest) -> Bool {
        return switch curve {
        case .p256:
            (key as! P256.Signing.PublicKey).isValidSignature(
                try! P256.Signing.ECDSASignature(derRepresentation: signature),
                for: digest.digest
            )

        case .p384:
            (key as! P384.Signing.PublicKey).isValidSignature(
                try! P384.Signing.ECDSASignature(derRepresentation: signature),
                for: digest.digest
            )

        case .p521:
            (key as! P521.Signing.PublicKey).isValidSignature(
                try! P521.Signing.ECDSASignature(derRepresentation: signature),
                for: digest.digest
            )
        }
    }

    @objc public func verifyRaw(signature: NSData, digest: DwcDigest) -> Bool {
        return switch curve {
        case .p256:
            (key as! P256.Signing.PublicKey).isValidSignature(
                try! P256.Signing.ECDSASignature(rawRepresentation: signature),
                for: digest.digest
            )

        case .p384:
            (key as! P384.Signing.PublicKey).isValidSignature(
                try! P384.Signing.ECDSASignature(rawRepresentation: signature),
                for: digest.digest
            )

        case .p521:
            (key as! P521.Signing.PublicKey).isValidSignature(
                try! P521.Signing.ECDSASignature(rawRepresentation: signature),
                for: digest.digest
            )
        }
    }

    @objc public func rawRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.Signing.PublicKey).x963Representation
        case .p384: return (key as! P384.Signing.PublicKey).x963Representation
        case .p521: return (key as! P521.Signing.PublicKey).x963Representation
        }
    }

    @objc public func compressedRepresentation() throws -> Data {
        guard #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) else {
            throw DwcCryptoKitError.unavailableOSVersion
        }
        switch curve {
        case .p256: return (key as! P256.Signing.PublicKey).compressedRepresentation
        case .p384: return (key as! P384.Signing.PublicKey).compressedRepresentation
        case .p521: return (key as! P521.Signing.PublicKey).compressedRepresentation
        }
    }

    @objc public func derRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.Signing.PublicKey).derRepresentation
        case .p384: return (key as! P384.Signing.PublicKey).derRepresentation
        case .p521: return (key as! P521.Signing.PublicKey).derRepresentation
        }
    }

    @objc public func pemRepresentation() -> String {
        switch curve {
        case .p256: return (key as! P256.Signing.PublicKey).pemRepresentation
        case .p384: return (key as! P384.Signing.PublicKey).pemRepresentation
        case .p521: return (key as! P521.Signing.PublicKey).pemRepresentation
        }
    }

    @objc public var curveType: DwcEcCurve { curve }
}

@objc public class DwcEcdsaPrivateKey: NSObject {
    private let key: Any
    private let curve: DwcEcCurve

    private init(key: Any, curve: DwcEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func generate(curve: DwcEcCurve) -> DwcEcdsaPrivateKey {
        switch curve {
        case .p256: return DwcEcdsaPrivateKey(key: P256.Signing.PrivateKey(), curve: .p256)
        case .p384: return DwcEcdsaPrivateKey(key: P384.Signing.PrivateKey(), curve: .p384)
        case .p521: return DwcEcdsaPrivateKey(key: P521.Signing.PrivateKey(), curve: .p521)
        }
    }

    @objc public static func decodeRaw(
        curve: DwcEcCurve,
        rawRepresentation: NSData
    )
        throws -> DwcEcdsaPrivateKey
    {
        switch curve {
        case .p256:
            return DwcEcdsaPrivateKey(
                key: try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdsaPrivateKey(
                key: try P384.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdsaPrivateKey(
                key: try P521.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: DwcEcCurve,
        derRepresentation: NSData
    ) throws -> DwcEcdsaPrivateKey {
        switch curve {
        case .p256:
            return DwcEcdsaPrivateKey(
                key: try P256.Signing.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return DwcEcdsaPrivateKey(
                key: try P384.Signing.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return DwcEcdsaPrivateKey(
                key: try P521.Signing.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: DwcEcCurve,
        pemRepresentation: String
    ) throws -> DwcEcdsaPrivateKey {
        switch curve {
        case .p256:
            return DwcEcdsaPrivateKey(
                key: try P256.Signing.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return DwcEcdsaPrivateKey(
                key: try P384.Signing.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return DwcEcdsaPrivateKey(
                key: try P521.Signing.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func signRaw(digest: DwcDigest) throws -> Data {
        return switch curve {
        case .p256:
            try (key as! P256.Signing.PrivateKey).signature(for: digest.digest).rawRepresentation
        case .p384:
            try (key as! P384.Signing.PrivateKey).signature(for: digest.digest).rawRepresentation
        case .p521:
            try (key as! P521.Signing.PrivateKey).signature(for: digest.digest).rawRepresentation
        }
    }

    @objc public func signDer(digest: DwcDigest) throws -> Data {
        return switch curve {
        case .p256:
            try (key as! P256.Signing.PrivateKey).signature(for: digest.digest).derRepresentation
        case .p384:
            try (key as! P384.Signing.PrivateKey).signature(for: digest.digest).derRepresentation
        case .p521:
            try (key as! P521.Signing.PrivateKey).signature(for: digest.digest).derRepresentation
        }
    }

    @objc public func publicKey() -> DwcEcdsaPublicKey {
        return switch curve {
        case .p256:
            DwcEcdsaPublicKey(key: (key as! P256.Signing.PrivateKey).publicKey, curve: .p256)
        case .p384:
            DwcEcdsaPublicKey(key: (key as! P384.Signing.PrivateKey).publicKey, curve: .p384)
        case .p521:
            DwcEcdsaPublicKey(key: (key as! P521.Signing.PrivateKey).publicKey, curve: .p521)
        }
    }

    @objc public func rawRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.Signing.PrivateKey).rawRepresentation
        case .p384: return (key as! P384.Signing.PrivateKey).rawRepresentation
        case .p521: return (key as! P521.Signing.PrivateKey).rawRepresentation
        }
    }

    @objc public func derRepresentation() -> Data {
        switch curve {
        case .p256: return (key as! P256.Signing.PrivateKey).derRepresentation
        case .p384: return (key as! P384.Signing.PrivateKey).derRepresentation
        case .p521: return (key as! P521.Signing.PrivateKey).derRepresentation
        }
    }

    @objc public func pemRepresentation() -> String {
        switch curve {
        case .p256: return (key as! P256.Signing.PrivateKey).pemRepresentation
        case .p384: return (key as! P384.Signing.PrivateKey).pemRepresentation
        case .p521: return (key as! P521.Signing.PrivateKey).pemRepresentation
        }
    }

    @objc public var curveType: DwcEcCurve { curve }
}
