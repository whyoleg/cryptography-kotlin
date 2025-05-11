import CryptoKit
import Foundation

@objc public class SwiftHash : NSObject {
    @objc(md5:) public class func md5(data: NSData) -> Data {
        return Data(Insecure.MD5.hash(data: data))
    }
    @objc(sha1:) public class func sha1(data: NSData) -> Data {
        return Data(Insecure.SHA1.hash(data: data))
    }
    @objc(sha256:) public class func sha256(data: NSData) -> Data {
        return Data(SHA256.hash(data: data))
    }
    @objc(sha384:) public class func sha384(data: NSData) -> Data {
        return Data(SHA384.hash(data: data))
    }
    @objc(sha512:) public class func sha512(data: NSData) -> Data {
        return Data(SHA512.hash(data: data))
    }
}
