package dev.whyoleg.cryptography.impl

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public enum class Md : CryptographyPrimitiveParameters<HashPrimitive> {
    MD2, MD4, MD5;
}
