/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoAsymmetricKeyGenerator<K : Key>(
    private val algorithm: AsymmetricKeyGenerationAlgorithm,
    private val keyUsages: Array<String>,
    private val keyPairWrapper: (CryptoKeyPair) -> K,
) : KeyGenerator<K> {
    override suspend fun generateKey(): K {
        return keyPairWrapper(WebCrypto.subtle.generateKey(algorithm, true, keyUsages).await())
    }

    override fun generateKeyBlocking(): K = nonBlocking()
}
