/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.materials.key.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SharedSecretGenerator<K : Key> {
    public suspend fun generateSharedSecret(other: K): BinaryData
    public fun generateSharedSecretBlocking(other: K): BinaryData
}
