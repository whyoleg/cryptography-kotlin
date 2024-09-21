/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

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

    override suspend fun hash(data: ByteArray): ByteArray {
        return WebCrypto.digest(algorithm, data)
    }

    @OptIn(UnsafeByteStringApi::class)
    override suspend fun hash(data: RawSource): ByteString {
        return UnsafeByteStringOperations.wrapUnsafe(hash(data.buffered().readByteArray()))
    }

    override fun createHashFunction(): HashFunction = nonBlocking()
    override fun hashBlocking(data: ByteArray): ByteArray = nonBlocking()
    override fun hashBlocking(data: RawSource): ByteString = nonBlocking()
}
