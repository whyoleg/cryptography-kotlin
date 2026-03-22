/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

/**
 * Generates new cryptographic keys of type [K].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyGenerator<K> {
    /**
     * Generates a new key and returns it.
     *
     * Use [generateKeyBlocking] when calling from non-suspending code.
     */
    public suspend fun generateKey(): K = generateKeyBlocking()

    /**
     * Generates a new key and returns it.
     *
     * Use [generateKey] when calling from suspending code.
     */
    public fun generateKeyBlocking(): K
}
