/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.provider

import java.util.*

internal interface CryptographyProviderContainer {
    val provider: Lazy<CryptographyProvider>
}

internal actual fun defaultCryptographyProvider(): CryptographyProvider {
    val cls = CryptographyProviderContainer::class.java
    return ServiceLoader.load(cls, cls.classLoader).first().provider.value
}
