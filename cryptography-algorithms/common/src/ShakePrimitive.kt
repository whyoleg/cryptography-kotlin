package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public enum class Md : CryptographyParameters<HashPrimitive> {
    MD2, MD4, MD5;
}

public sealed class Shake(public val digestSize: BinarySize) : CryptographyParameters<HashPrimitive>
public class Shake128(digestSize: BinarySize) : Shake(digestSize)
public class Shake256(digestSize: BinarySize) : Shake(digestSize)
