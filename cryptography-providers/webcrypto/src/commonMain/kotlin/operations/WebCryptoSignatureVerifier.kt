/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.operations

import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoSignatureVerifier(
    private val algorithm: Algorithm,
    private val key: CryptoKey,
) : SignatureVerifier {
    override suspend fun verifySignature(data: ByteArray, signature: ByteArray): Boolean {
        return WebCrypto.verify(algorithm, key, signature, data)
    }

    override fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean = nonBlocking()
}
