/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SharedSecretGenerator<K> {
    public suspend fun generateSharedSecretToByteArray(other: K): ByteArray {
        return generateSharedSecretToByteArrayBlocking(other)
    }

    public suspend fun generateSharedSecret(other: K): ByteString {
        return generateSharedSecretToByteArray(other).asByteString()
    }

    public fun generateSharedSecretToByteArrayBlocking(other: K): ByteArray

    public fun generateSharedSecretBlocking(other: K): ByteString {
        return generateSharedSecretToByteArrayBlocking(other).asByteString()
    }
}
