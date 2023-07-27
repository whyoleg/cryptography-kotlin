/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*

import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.external.*

internal class WebCryptoDigest private constructor(
    private val algorithm: String,
    override val id: CryptographyAlgorithmId<Digest>,
) : Digest, Hasher {
    companion object {
        val sha1 = WebCryptoDigest("SHA-1", SHA1)
        val sha256 = WebCryptoDigest("SHA-256", SHA256)
        val sha384 = WebCryptoDigest("SHA-384", SHA384)
        val sha512 = WebCryptoDigest("SHA-512", SHA512)
    }

    override fun hasher(): Hasher = this

    override suspend fun hash(dataInput: ByteArray): ByteArray {
        return WebCrypto.subtle.digest(algorithm, dataInput).await().toByteArray()
    }

    override fun hashBlocking(dataInput: ByteArray): ByteArray = nonBlocking()
}
