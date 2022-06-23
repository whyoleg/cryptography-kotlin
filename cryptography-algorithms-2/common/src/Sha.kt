package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public enum class Sha : CryptographyParameters<HashPrimitive> {
    SHA1,
    SHA256, SHA512,
    SHA3_256, SHA3_512;
}
