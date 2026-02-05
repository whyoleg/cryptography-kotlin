/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PublicKeyAccessor<PublicK> {
    public suspend fun getPublicKey(): PublicK = getPublicKeyBlocking()
    public fun getPublicKeyBlocking(): PublicK
}
