/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

internal class WebCryptoSignatureGenerator(
    private val algorithm: Algorithm,
    private val key: CryptoKey,
) : SignatureGenerator {
    override suspend fun generateSignature(data: ByteArray): ByteArray {
        return WebCrypto.sign(algorithm, key, data)
    }

    @OptIn(UnsafeByteStringApi::class)
    override suspend fun generateSignature(data: RawSource): ByteString {
        return UnsafeByteStringOperations.wrapUnsafe(generateSignature(data.buffered().readByteArray()))
    }

    override fun createSignFunction(): SignFunction = nonBlocking()
    override fun generateSignatureBlocking(data: ByteArray): ByteArray = nonBlocking()
    override fun generateSignatureBlocking(data: RawSource): ByteString = nonBlocking()
}
