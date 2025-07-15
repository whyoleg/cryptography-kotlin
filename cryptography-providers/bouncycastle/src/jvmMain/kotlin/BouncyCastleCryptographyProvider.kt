/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.bouncycastle

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.algorithms.*
import dev.whyoleg.cryptography.random.*
import java.security.*
import java.util.*
import java.util.concurrent.*

private val defaultProvider = lazy { BouncyCastleCryptographyProvider }

internal object BouncyCastleCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "BouncyCastle"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        HKDF -> JdkHkdf(state, this)
        else -> null
    } as A?
}

internal class BouncyCastleCryptographyProviderContainer : CryptographyProviderContainer {
    override val priority: Int get() = 100
    override val provider: Lazy<CryptographyProvider> get() = defaultProvider
}
