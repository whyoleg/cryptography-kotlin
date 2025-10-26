import CryptoKit
import Foundation

@objc public class SwiftEdDsaPublicKey: NSObject {
    private let key: Curve25519.Signing.PublicKey

    internal init(_ key: Curve25519.Signing.PublicKey) { self.key = key }

    @objc public static func decodeRaw(
        rawRepresentation raw: NSData
    ) throws -> SwiftEdDsaPublicKey {
        return SwiftEdDsaPublicKey(try Curve25519.Signing.PublicKey(rawRepresentation: raw as Data))
    }

    @objc public func verify(
        signature: NSData,
        message: NSData
    ) -> Bool {
        return key.isValidSignature(signature as Data, for: message as Data)
    }

    @objc public func rawRepresentation() -> Data { key.rawRepresentation }
}

@objc public class SwiftEdDsaPrivateKey: NSObject {
    private let key: Curve25519.Signing.PrivateKey

    private override init() { self.key = Curve25519.Signing.PrivateKey() }
    private init(key: Curve25519.Signing.PrivateKey) { self.key = key }

    @objc public static func generate() -> SwiftEdDsaPrivateKey { SwiftEdDsaPrivateKey() }

    @objc public static func decodeRaw(
        rawRepresentation raw: NSData
    ) throws -> SwiftEdDsaPrivateKey {
        return SwiftEdDsaPrivateKey(key: try Curve25519.Signing.PrivateKey(rawRepresentation: raw as Data))
    }

    @objc public func publicKey() -> SwiftEdDsaPublicKey { SwiftEdDsaPublicKey(key.publicKey) }

    @objc public func sign(
        message: NSData
    ) throws -> Data {
        try key.signature(for: message as Data)
    }

    @objc public func rawRepresentation() -> Data { key.rawRepresentation }
}

@objc public class SwiftXdhPublicKey: NSObject {
    let key: Curve25519.KeyAgreement.PublicKey
    internal init(_ key: Curve25519.KeyAgreement.PublicKey) { self.key = key }

    @objc public static func decodeRaw(
        rawRepresentation raw: NSData
    ) throws -> SwiftXdhPublicKey {
        return SwiftXdhPublicKey(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw as Data))
    }

    @objc public func rawRepresentation() -> Data { key.rawRepresentation }
}

@objc public class SwiftXdhPrivateKey: NSObject {
    let key: Curve25519.KeyAgreement.PrivateKey
    private override init() { self.key = Curve25519.KeyAgreement.PrivateKey() }
    private init(_ key: Curve25519.KeyAgreement.PrivateKey) { self.key = key }

    @objc public static func generate() -> SwiftXdhPrivateKey { SwiftXdhPrivateKey() }

    @objc public static func decodeRaw(
        rawRepresentation raw: NSData
    ) throws -> SwiftXdhPrivateKey {
        return SwiftXdhPrivateKey(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw as Data))
    }

    @objc public func publicKey() -> SwiftXdhPublicKey { SwiftXdhPublicKey(key.publicKey) }

    @objc public func deriveSecret(
        with publicKey: SwiftXdhPublicKey
    ) throws -> Data {
        let ss = try key.sharedSecretFromKeyAgreement(with: publicKey.key)
        return ss.withUnsafeBytes { Data($0) }
    }

    @objc public func rawRepresentation() -> Data { key.rawRepresentation }
}

