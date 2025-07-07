/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyGenerator<K : Key> : MaterialGenerator<K> {
    // TODO: deprecate those in favor of `generate()`
    public suspend fun generateKey(): K = generateKeyBlocking()
    public fun generateKeyBlocking(): K
}
