/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.operations


import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.external.*

internal class WebCryptoSignatureGenerator(
    private val algorithm: SignAlgorithm,
    private val key: CryptoKey,
) : SignatureGenerator {
    override suspend fun generateSignature(dataInput: ByteArray): ByteArray {
        return WebCrypto.subtle.sign(algorithm, key, dataInput).await().toByteArray()
    }

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = nonBlocking()
}
