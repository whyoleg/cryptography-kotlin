/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.external.*

internal class WebCryptoSymmetricKeyGenerator<K : Key>(
    private val algorithm: SymmetricKeyGenerationAlgorithm,
    private val keyUsages: Array<String>,
    private val keyWrapper: (CryptoKey) -> K,
) : KeyGenerator<K> {
    override suspend fun generateKey(): K {
        return keyWrapper(WebCrypto.subtle.generateKey(algorithm, true, keyUsages).await())
    }

    override fun generateKeyBlocking(): K = nonBlocking()
}
