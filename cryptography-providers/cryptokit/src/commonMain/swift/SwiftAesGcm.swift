import CryptoKit
import Foundation

@objc public class SwiftAesGcm: NSObject {
    @objc public static func encrypt(
        key: NSData,
        nonce: NSData,
        plaintext: NSData,
        authenticatedData: NSData
    ) throws -> Data {
        return try AES.GCM.seal(
            plaintext as Data,
            using: SymmetricKey(data: key as Data),
            nonce: try AES.GCM.Nonce(data: nonce as Data),
            authenticating: authenticatedData
        ).combined!
    }

    @objc public static func decrypt(
        key: NSData,
        nonce: NSData,
        ciphertext: NSData,
        tag: NSData,
        authenticatedData: NSData
    ) throws -> Data {
        return try AES.GCM.open(
            try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            ),
            using: SymmetricKey(data: key as Data),
            authenticating: authenticatedData
        )
    }
}
