/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.base.*

internal fun CryptographyAlgorithmId<Digest>.blockSizeBits(): Int = when (this) {
    SHA1   -> 64
    SHA256 -> 64
    SHA384 -> 128
    SHA512 -> 128
    else -> unsupportedParameter("hash algorithm", name)
} * 8

internal fun CryptographyAlgorithmId<Digest>?.hashAlgorithmName(): String = when (this) {
    SHA1   -> "SHA-1"
    SHA256 -> "SHA-256"
    SHA384 -> "SHA-384"
    SHA512 -> "SHA-512"
    null   -> throw IllegalStateException("Operation without digest is unsupported!")
    else -> unsupportedParameter("hash algorithm", name)
}

internal fun CryptographyAlgorithmId<Digest>.digestSize(): Int = when (this) {
    SHA1   -> 20
    SHA256 -> 32
    SHA384 -> 48
    SHA512 -> 64
    else -> unsupportedParameter("hash algorithm", name)
}

internal fun hashSize(hashAlgorithmName: String): Int = when (hashAlgorithmName) {
    "SHA-1"   -> 20
    "SHA-256" -> 32
    "SHA-384" -> 48
    "SHA-512" -> 64
    else -> unsupportedParameter("hash algorithm", hashAlgorithmName)
}
