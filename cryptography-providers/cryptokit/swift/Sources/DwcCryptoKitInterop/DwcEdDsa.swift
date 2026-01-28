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
