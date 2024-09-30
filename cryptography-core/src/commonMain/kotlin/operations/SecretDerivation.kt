/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation {
    public suspend fun deriveSecretToByteArray(input: ByteArray): ByteArray {
        return deriveSecretToByteArrayBlocking(input)
    }

    public suspend fun deriveSecretToByteArray(input: ByteString): ByteArray {
        return deriveSecretToByteArray(input.asByteArray())
    }

    public suspend fun deriveSecret(input: ByteArray): ByteString {
        return deriveSecretToByteArray(input).asByteString()
    }

    public suspend fun deriveSecret(input: ByteString): ByteString {
        return deriveSecretToByteArray(input.asByteArray()).asByteString()
    }

    public fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray

    public fun deriveSecretToByteArrayBlocking(input: ByteString): ByteArray {
        return deriveSecretToByteArrayBlocking(input.asByteArray())
    }

    public fun deriveSecretBlocking(input: ByteArray): ByteString {
        return deriveSecretToByteArrayBlocking(input).asByteString()
    }

    public fun deriveSecretBlocking(input: ByteString): ByteString {
        return deriveSecretToByteArrayBlocking(input.asByteArray()).asByteString()
    }
}
