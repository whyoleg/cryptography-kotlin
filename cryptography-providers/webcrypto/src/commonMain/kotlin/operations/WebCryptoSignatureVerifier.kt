/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.operations

import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoSignatureVerifier(
    private val algorithm: Algorithm,
    private val key: CryptoKey,
) : SignatureVerifier {
    override suspend fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        return WebCrypto.verify(algorithm, key, signatureInput, dataInput)
    }

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = nonBlocking()
}
