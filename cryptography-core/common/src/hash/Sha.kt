package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public enum class Sha(override val digestSize: DigestSize) : HashParameters {
    SHA1(DigestSize(160.bits)),
    SHA256(DigestSize(256.bits)), SHA512(DigestSize(512.bits)),
    SHA3_256(DigestSize(256.bits)), SHA3_512(DigestSize(512.bits));
}
