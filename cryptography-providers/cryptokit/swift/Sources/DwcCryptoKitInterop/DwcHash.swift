import CryptoKit
import Foundation

@objc public enum DwcHashAlgorithm: Int {
    case md5
    case sha1
    case sha256
    case sha384
    case sha512
}

@objc public class DwcHashFunction: NSObject {
    private let algorithm: DwcHashAlgorithm
    private var function: any HashFunction

    @objc public init(algorithm: DwcHashAlgorithm) {
        self.algorithm = algorithm
        self.function =
            switch algorithm {
            case .md5: Insecure.MD5()
            case .sha1: Insecure.SHA1()
            case .sha256: SHA256()
            case .sha384: SHA384()
            case .sha512: SHA512()
            }
        super.init()
    }

    @objc(doUpdate:) public func doUpdate(data: NSData) {
        function.update(data: data)
    }

    @objc public func doFinal() -> Data {
        return switch algorithm {
        case .md5: Data((function as! Insecure.MD5).finalize())
        case .sha1: Data((function as! Insecure.SHA1).finalize())
        case .sha256: Data((function as! SHA256).finalize())
        case .sha384: Data((function as! SHA384).finalize())
        case .sha512: Data((function as! SHA512).finalize())
        }
    }

    @objc public func doFinalDigest() -> DwcDigest {
        return switch algorithm {
        case .md5: DwcDigest(digest: (function as! Insecure.MD5).finalize())
        case .sha1: DwcDigest(digest: (function as! Insecure.SHA1).finalize())
        case .sha256: DwcDigest(digest: (function as! SHA256).finalize())
        case .sha384: DwcDigest(digest: (function as! SHA384).finalize())
        case .sha512: DwcDigest(digest: (function as! SHA512).finalize())
        }
    }
}

@objc public class DwcDigest: NSObject {
    internal let digest: any Digest
    internal init(digest: any Digest) {
        self.digest = digest
    }
}
