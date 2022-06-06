package dev.whyoleg.cryptography.impl

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public sealed class Shake(public val digestSize: DigestSize) : CryptographyPrimitiveParameters<HashPrimitive> {
    public class SHAKE128(digestSize: DigestSize) : Shake(digestSize)
    public class SHAKE256(digestSize: DigestSize) : Shake(digestSize)
}
