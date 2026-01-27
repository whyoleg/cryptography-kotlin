import CryptoKit
import Foundation

@objc public class DwcX25519PublicKey: NSObject {
    private let key: Curve25519.KeyAgreement.PublicKey

    internal init(key: Curve25519.KeyAgreement.PublicKey) {
        self.key = key
    }

    @objc public static func decodeRaw(
        rawRepresentation: NSData
    ) throws -> DwcX25519PublicKey {
        return DwcX25519PublicKey(
            key: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation as Data)
        )
    }

    @objc public func rawRepresentation() -> Data {
        return key.rawRepresentation
    }

    internal func deriveSecret(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: key)
        return secret.withUnsafeBytes { Data($0) }
    }
}

@objc public class DwcX25519PrivateKey: NSObject {
    private let key: Curve25519.KeyAgreement.PrivateKey

    private init(key: Curve25519.KeyAgreement.PrivateKey) {
        self.key = key
    }

    @objc public static func generate() -> DwcX25519PrivateKey {
        return DwcX25519PrivateKey(key: Curve25519.KeyAgreement.PrivateKey())
    }

    @objc public static func decodeRaw(
        rawRepresentation: NSData
    ) throws -> DwcX25519PrivateKey {
        return DwcX25519PrivateKey(
            key: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation as Data)
        )
    }

    @objc public func deriveSecret(publicKey: DwcX25519PublicKey) throws -> Data {
        return try publicKey.deriveSecret(privateKey: key)
    }

    @objc public func publicKey() -> DwcX25519PublicKey {
        return DwcX25519PublicKey(key: key.publicKey)
    }

    @objc public func rawRepresentation() -> Data {
        return key.rawRepresentation
    }
}