/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import java.util.*

@CryptographyProviderApi
public interface CryptographyProviderContainer {
    public val provider: Lazy<CryptographyProvider>
}

@OptIn(CryptographyProviderApi::class)
internal actual fun initProviders(): List<Lazy<CryptographyProvider>> = Iterable {
    ServiceLoader.load(
        CryptographyProviderContainer::class.java,
        CryptographyProviderContainer::class.java.classLoader
    ).iterator()
}.map { it.provider }
