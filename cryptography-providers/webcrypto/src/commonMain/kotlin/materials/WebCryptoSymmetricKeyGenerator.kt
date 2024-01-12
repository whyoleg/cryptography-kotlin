/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoSymmetricKeyGenerator<K : Key>(
    private val algorithm: Algorithm,
    private val keyUsages: Array<String>,
    private val keyWrapper: (CryptoKey) -> K,
) : KeyGenerator<K> {
    override suspend fun generateKey(): K {
        return keyWrapper(WebCrypto.generateKey(algorithm, true, keyUsages))
    }

    override fun generateKeyBlocking(): K = nonBlocking()
}
