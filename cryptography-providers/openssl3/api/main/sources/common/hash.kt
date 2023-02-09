package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*

internal fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): String = when (digest) {
    SHA1   -> "SHA1"
    SHA256 -> "SHA256"
    SHA384 -> "SHA384"
    SHA512 -> "SHA512"
    else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
}
