/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyGenerator<K : Key> : MaterialGenerator<K> {
    @Deprecated(
        "Renamed to generate",
        ReplaceWith("generate()"),
        level = DeprecationLevel.ERROR,
    )
    public suspend fun generateKey(): K = generate()

    @Deprecated(
        "Renamed to generateBlocking",
        ReplaceWith("generateBlocking()"),
        level = DeprecationLevel.ERROR,
    )
    public fun generateKeyBlocking(): K = generateBlocking()
}
