import CryptoKit
import Foundation

@objc public class SwiftHkdf: NSObject {

    @objc public static func derive(
        algorithm: SwiftHashAlgorithm,
        inputKey: NSData,
        salt: NSData,
        info: NSData,
        outputSize: Int
    ) -> Data {
        let ikm = SymmetricKey(data: inputKey as Data)
        let outputKey =
            switch algorithm {
            case .md5:
                HKDF<Insecure.MD5>.deriveKey(
                    inputKeyMaterial: ikm,
                    salt: salt,
                    info: info,
                    outputByteCount: outputSize
                )

            case .sha1:
                HKDF<Insecure.SHA1>.deriveKey(
                    inputKeyMaterial: ikm,
                    salt: salt,
                    info: info,
                    outputByteCount: outputSize
                )

            case .sha256:
                HKDF<SHA256>.deriveKey(
                    inputKeyMaterial: ikm,
                    salt: salt,
                    info: info,
                    outputByteCount: outputSize
                )

            case .sha384:
                HKDF<SHA384>.deriveKey(
                    inputKeyMaterial: ikm,
                    salt: salt,
                    info: info,
                    outputByteCount: outputSize
                )

            case .sha512:
                HKDF<SHA512>.deriveKey(
                    inputKeyMaterial: ikm,
                    salt: salt,
                    info: info,
                    outputByteCount: outputSize
                )
            }
        return outputKey.withUnsafeBytes { Data($0) }
    }
}
