import CryptoKit
import Foundation

@objc public class SwiftHmacFunction: NSObject {
    private var wrapper: AnyHmacWrapper

    @objc public init(algorithm: SwiftHashAlgorithm, key: NSData) {
        let secretKey = SymmetricKey(data: key as Data)
        self.wrapper = switch algorithm {
            case .md5:    HmacWrapper<Insecure.MD5>(key: secretKey)
            case .sha1:   HmacWrapper<Insecure.SHA1>(key: secretKey)
            case .sha256: HmacWrapper<SHA256>(key: secretKey)
            case .sha384: HmacWrapper<SHA384>(key: secretKey)
            case .sha512: HmacWrapper<SHA512>(key: secretKey)
        }
        super.init()
    }

    @objc(doUpdate:) public func doUpdate(data: NSData) {
        wrapper.doUpdate(data: data)
    }

    @objc public func doFinal() -> Data {
        return Data(wrapper.doFinal())
    }
}

fileprivate protocol AnyHmacWrapper {
    func doUpdate(data: NSData)
    func doFinal() -> Data
}

fileprivate final class HmacWrapper<H: HashFunction>: AnyHmacWrapper where H.Digest: ContiguousBytes {
    private var value: HMAC<H>

    init(key: SymmetricKey) {
        self.value = HMAC<H>(key: key)
    }

    func doUpdate(data: NSData) {
        value.update(data: data)
    }

    func doFinal() -> Data {
        return Data(value.finalize())
    }
}
