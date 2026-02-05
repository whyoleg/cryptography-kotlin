/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyGenerator<K> {
    public suspend fun generateKey(): K = generateKeyBlocking()
    public fun generateKeyBlocking(): K
}
