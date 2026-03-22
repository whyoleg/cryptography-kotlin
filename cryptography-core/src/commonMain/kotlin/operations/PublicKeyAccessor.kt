/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

/**
 * Provides access to the associated public key of type [PublicK].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PublicKeyAccessor<PublicK> {
    /**
     * Returns the associated public key.
     *
     * Use [getPublicKeyBlocking] when calling from non-suspending code.
     */
    public suspend fun getPublicKey(): PublicK = getPublicKeyBlocking()

    /**
     * Returns the associated public key.
     *
     * Use [getPublicKey] when calling from suspending code.
     */
    public fun getPublicKeyBlocking(): PublicK
}
