import CryptoKit
import Foundation

@objc public enum SwiftEcCurve: Int {
    case p256, p384, p521
}

@objc public class SwiftEcdsaPublicKey: NSObject {
    private let key: Any
    private let curve: SwiftEcCurve

    internal init(key: Any, curve: SwiftEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func decodeRaw(
        curve: SwiftEcCurve,
        rawRepresentation: NSData
    )
        throws -> SwiftEcdsaPublicKey
    {
        switch curve {
        case .p256:
            return SwiftEcdsaPublicKey(
                key: try P256.Signing.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdsaPublicKey(
                key: try P384.Signing.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdsaPublicKey(
                key: try P521.Signing.PublicKey(x963Representation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: SwiftEcCurve,
        derRepresentation: NSData
    ) throws -> SwiftEcdsaPublicKey {
        switch curve {
        case .p256:
            return SwiftEcdsaPublicKey(
                key: try P256.Signing.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdsaPublicKey(
                key: try P384.Signing.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdsaPublicKey(
                key: try P521.Signing.PublicKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: SwiftEcCurve,
        pemRepresentation: String
    ) throws -> SwiftEcdsaPublicKey {
        switch curve {
        case .p256:
            return SwiftEcdsaPublicKey(
                key: try P256.Signing.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return SwiftEcdsaPublicKey(
                key: try P384.Signing.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return SwiftEcdsaPublicKey(
                key: try P521.Signing.PublicKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func verifyDer(signature: NSData, digest: SwiftDigest) -> Bool {
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

    @objc public func verifyRaw(signature: NSData, digest: SwiftDigest) -> Bool {
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

    @objc public var curveType: SwiftEcCurve { curve }
}

@objc public class SwiftEcdsaPrivateKey: NSObject {
    private let key: Any
    private let curve: SwiftEcCurve

    private init(key: Any, curve: SwiftEcCurve) {
        self.key = key
        self.curve = curve
    }

    @objc public static func generate(curve: SwiftEcCurve) -> SwiftEcdsaPrivateKey {
        switch curve {
        case .p256: return SwiftEcdsaPrivateKey(key: P256.Signing.PrivateKey(), curve: .p256)
        case .p384: return SwiftEcdsaPrivateKey(key: P384.Signing.PrivateKey(), curve: .p384)
        case .p521: return SwiftEcdsaPrivateKey(key: P521.Signing.PrivateKey(), curve: .p521)
        }
    }

    @objc public static func decodeRaw(
        curve: SwiftEcCurve,
        rawRepresentation: NSData
    )
        throws -> SwiftEcdsaPrivateKey
    {
        switch curve {
        case .p256:
            return SwiftEcdsaPrivateKey(
                key: try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdsaPrivateKey(
                key: try P384.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdsaPrivateKey(
                key: try P521.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodeDer(
        curve: SwiftEcCurve,
        derRepresentation: NSData
    ) throws -> SwiftEcdsaPrivateKey {
        switch curve {
        case .p256:
            return SwiftEcdsaPrivateKey(
                key: try P256.Signing.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p256)
        case .p384:
            return SwiftEcdsaPrivateKey(
                key: try P384.Signing.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p384)
        case .p521:
            return SwiftEcdsaPrivateKey(
                key: try P521.Signing.PrivateKey(derRepresentation: derRepresentation as Data),
                curve: .p521)
        }
    }

    @objc public static func decodePem(
        curve: SwiftEcCurve,
        pemRepresentation: String
    ) throws -> SwiftEcdsaPrivateKey {
        switch curve {
        case .p256:
            return SwiftEcdsaPrivateKey(
                key: try P256.Signing.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p256)
        case .p384:
            return SwiftEcdsaPrivateKey(
                key: try P384.Signing.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p384)
        case .p521:
            return SwiftEcdsaPrivateKey(
                key: try P521.Signing.PrivateKey(pemRepresentation: pemRepresentation),
                curve: .p521)
        }
    }

    @objc public func signRaw(digest: SwiftDigest) throws -> Data {
        return switch curve {
        case .p256:
            try (key as! P256.Signing.PrivateKey).signature(for: digest.digest).rawRepresentation
        case .p384:
            try (key as! P384.Signing.PrivateKey).signature(for: digest.digest).rawRepresentation
        case .p521:
            try (key as! P521.Signing.PrivateKey).signature(for: digest.digest).rawRepresentation
        }
    }

    @objc public func signDer(digest: SwiftDigest) throws -> Data {
        return switch curve {
        case .p256:
            try (key as! P256.Signing.PrivateKey).signature(for: digest.digest).derRepresentation
        case .p384:
            try (key as! P384.Signing.PrivateKey).signature(for: digest.digest).derRepresentation
        case .p521:
            try (key as! P521.Signing.PrivateKey).signature(for: digest.digest).derRepresentation
        }
    }

    @objc public func publicKey() -> SwiftEcdsaPublicKey {
        return switch curve {
        case .p256:
            SwiftEcdsaPublicKey(key: (key as! P256.Signing.PrivateKey).publicKey, curve: .p256)
        case .p384:
            SwiftEcdsaPublicKey(key: (key as! P384.Signing.PrivateKey).publicKey, curve: .p384)
        case .p521:
            SwiftEcdsaPublicKey(key: (key as! P521.Signing.PrivateKey).publicKey, curve: .p521)
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

    @objc public var curveType: SwiftEcCurve { curve }
}
