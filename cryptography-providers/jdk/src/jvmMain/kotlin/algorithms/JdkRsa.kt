/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*

//rsa JDK uses slightly different names for hash algorithms
internal fun CryptographyAlgorithmId<Digest>.rsaHashAlgorithmName(): String = when (this) {
    SHA1     -> "SHA-1"
    SHA224   -> "SHA-224"
    SHA256   -> "SHA-256"
    SHA384   -> "SHA-384"
    SHA512   -> "SHA-512"
    SHA3_224 -> "SHA3-224"
    SHA3_256 -> "SHA3-256"
    SHA3_384 -> "SHA3-384"
    SHA3_512 -> "SHA3-512"
    else     -> throw CryptographyException("Unsupported hash algorithm: $this")
}
