/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*


internal fun hashAlgorithmName(digest: CryptographyAlgorithmId<Digest>): String = when (digest) {
    SHA1     -> "SHA1"
    SHA224   -> "SHA224"
    SHA256   -> "SHA256"
    SHA384   -> "SHA384"
    SHA512   -> "SHA512"
    SHA3_224 -> "SHA3-224"
    SHA3_256 -> "SHA3-256"
    SHA3_384 -> "SHA3-384"
    SHA3_512 -> "SHA3-512"
    else -> throw IllegalStateException("Unsupported hash algorithm: $digest")
}

internal fun digestSize(hashAlgorithm: String): Int {
    val md = checkError(EVP_MD_fetch(null, hashAlgorithm, null))
    try {
        return EVP_MD_get_size(md)
    } finally {
        EVP_MD_free(md)
    }
}

internal fun blockSize(hashAlgorithm: String): Int {
    val md = checkError(EVP_MD_fetch(null, hashAlgorithm, null))
    try {
        return EVP_MD_get_block_size(md)
    } finally {
        EVP_MD_free(md)
    }
}
