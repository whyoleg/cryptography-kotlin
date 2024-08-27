/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.binary.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation {
    public suspend fun deriveSecret(input: BinaryData): BinaryData
    public fun deriveSecretBlocking(input: BinaryData): BinaryData
}
