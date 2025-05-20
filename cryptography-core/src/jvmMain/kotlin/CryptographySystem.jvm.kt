/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import java.util.*

@CryptographyProviderApi
public interface CryptographyProviderContainer {
    public val priority: Int
    public val provider: Lazy<CryptographyProvider>
}

@OptIn(CryptographyProviderApi::class)
internal actual fun CryptographySystem.loadProviders() {
    loadViaServiceLoader().forEach {
        registerProvider(it.provider, it.priority)
    }
}

// uses specific calling convention to be optimized by R8
@OptIn(CryptographyProviderApi::class)
private fun loadViaServiceLoader(): Iterable<CryptographyProviderContainer> = Iterable {
    ServiceLoader.load(
        CryptographyProviderContainer::class.java,
        CryptographyProviderContainer::class.java.classLoader
    ).iterator()
}
