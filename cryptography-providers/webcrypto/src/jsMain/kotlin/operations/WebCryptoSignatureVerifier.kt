/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto.operations


import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoSignatureVerifier(
    private val algorithm: VerifyAlgorithm,
    private val key: CryptoKey,
) : SignatureVerifier {
    override suspend fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        return WebCrypto.subtle.verify(algorithm, key, signatureInput, dataInput).await()
    }

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = nonBlocking()
}
