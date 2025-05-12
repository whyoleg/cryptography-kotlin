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

@objc public enum SwiftHashAlgorithm: Int {
    case md5
    case sha1
    case sha256
    case sha384
    case sha512
}

@objc public class SwiftHashFunction: NSObject {
    private let algorithm: SwiftHashAlgorithm
    private var function: any HashFunction

    @objc public init(algorithm: SwiftHashAlgorithm) {
        self.algorithm = algorithm
        switch algorithm {
            case .md5:    function = Insecure.MD5()
            case .sha1:   function = Insecure.SHA1()
            case .sha256: function = SHA256()
            case .sha384: function = SHA384()
            case .sha512: function = SHA512()
        }
        super.init()
    }

    @objc(doUpdate:) public func doUpdate(data: NSData) {
        function.update(data: data)
    }

    @objc public func doFinal() -> Data {
        return switch algorithm {
            case .md5:    Data((function as! Insecure.MD5).finalize())
            case .sha1:   Data((function as! Insecure.SHA1).finalize())
            case .sha256: Data((function as! SHA256).finalize())
            case .sha384: Data((function as! SHA384).finalize())
            case .sha512: Data((function as! SHA512).finalize())
        }
    }
}
