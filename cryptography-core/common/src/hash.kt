package dev.whyoleg.cryptography

import dev.whyoleg.vio.*


//public enum class Md : HashParameters {
//    MD2, MD4, MD5;
//}

public enum class Sha(override val digestSize: DigestSize) : HashParameters {
    SHA1(DigestSize(160.bits)),
    SHA256(DigestSize(256.bits)), SHA512(DigestSize(512.bits)),
    SHA3_256(DigestSize(256.bits)), SHA3_512(DigestSize(512.bits));
}

public sealed class Shake(override val digestSize: DigestSize) : HashParameters {
    public class SHAKE128(digestSize: DigestSize) : Shake(digestSize)
    public class SHAKE256(digestSize: DigestSize) : Shake(digestSize)
}
