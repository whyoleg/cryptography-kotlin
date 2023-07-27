/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

private val providers = mutableListOf<Lazy<CryptographyProvider>>()

@PublishedApi
internal fun registerProvider(block: () -> CryptographyProvider): Unit = registerProvider(lazy(block))

@PublishedApi
internal fun registerProvider(lazy: Lazy<CryptographyProvider>) {
    providers += lazy
}

internal actual fun defaultCryptographyProvider(): CryptographyProvider = providers.first().value
