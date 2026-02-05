/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoSymmetricKeyGenerator<K>(
    private val algorithm: Algorithm,
    private val keyWrapper: WebCryptoKeyWrapper<K>,
) : KeyGenerator<K> {
    override suspend fun generateKey(): K = keyWrapper.wrap(
        WebCrypto.generateKey(
            algorithm = algorithm,
            extractable = true,
            keyUsages = keyWrapper.usages
        )
    )

    override fun generateKeyBlocking(): K = nonBlocking()
}
