import CryptoKit
import Foundation

@objc public class DwcEd25519PublicKey: NSObject {
    private let key: Curve25519.Signing.PublicKey

    internal init(key: Curve25519.Signing.PublicKey) {
        self.key = key
    }

    @objc public static func decodeRaw(
        rawRepresentation: NSData
    ) throws -> DwcEd25519PublicKey {
        return DwcEd25519PublicKey(
            key: try Curve25519.Signing.PublicKey(rawRepresentation: rawRepresentation as Data)
        )
    }

    @objc public func verify(signature: NSData, data: NSData) -> Bool {
        return key.isValidSignature(signature as Data, for: data as Data)
    }

    @objc public func rawRepresentation() -> Data {
        return key.rawRepresentation
    }
}

@objc public class DwcEd25519PrivateKey: NSObject {
    private let key: Curve25519.Signing.PrivateKey

    private init(key: Curve25519.Signing.PrivateKey) {
        self.key = key
    }

    @objc public static func generate() -> DwcEd25519PrivateKey {
        return DwcEd25519PrivateKey(key: Curve25519.Signing.PrivateKey())
    }

    @objc public static func decodeRaw(
        rawRepresentation: NSData
    ) throws -> DwcEd25519PrivateKey {
        return DwcEd25519PrivateKey(
            key: try Curve25519.Signing.PrivateKey(rawRepresentation: rawRepresentation as Data)
        )
    }

    @objc public func sign(data: NSData) throws -> Data {
        return try key.signature(for: data as Data)
    }

    @objc public func publicKey() -> DwcEd25519PublicKey {
        return DwcEd25519PublicKey(key: key.publicKey)
    }

    @objc public func rawRepresentation() -> Data {
        return key.rawRepresentation
    }
}
