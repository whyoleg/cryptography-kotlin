/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.operations

import dev.whyoleg.cryptography.functions.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

internal class WebCryptoSignatureVerifier(
    private val algorithm: Algorithm,
    private val key: CryptoKey,
) : SignatureVerifier {
    override suspend fun tryVerifySignature(data: ByteArray, signature: ByteArray): Boolean {
        return WebCrypto.verify(algorithm, key, signature, data)
    }

    @OptIn(UnsafeByteStringApi::class)
    override suspend fun tryVerifySignature(data: RawSource, signature: ByteString): Boolean {
        UnsafeByteStringOperations.withByteArrayUnsafe(signature) {
            return tryVerifySignature(data.buffered().readByteArray(), it)
        }
    }

    override fun createVerifyFunction(): VerifyFunction = nonBlocking()
    override fun tryVerifySignatureBlocking(data: RawSource, signature: ByteString): Boolean = nonBlocking()
    override fun tryVerifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean = nonBlocking()
}
