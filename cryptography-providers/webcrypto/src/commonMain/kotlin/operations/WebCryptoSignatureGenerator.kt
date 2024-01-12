/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.operations

import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoSignatureGenerator(
    private val algorithm: Algorithm,
    private val key: CryptoKey,
) : SignatureGenerator {
    override suspend fun generateSignature(dataInput: ByteArray): ByteArray {
        return WebCrypto.sign(algorithm, key, dataInput)
    }

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = nonBlocking()
}
