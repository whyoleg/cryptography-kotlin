/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

/**
 * Performs key agreement to produce a shared secret with the other party's key.
 *
 * The raw shared secret should not be used directly as an encryption key.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SharedSecretGenerator<K> {
    /**
     * Performs key agreement with the [other] party's key material
     * and returns the resulting shared secret as a [ByteArray].
     *
     * Use [generateSharedSecretToByteArrayBlocking] when calling from non-suspending code.
     */
    public suspend fun generateSharedSecretToByteArray(other: K): ByteArray {
        return generateSharedSecretToByteArrayBlocking(other)
    }

    /**
     * Performs key agreement with the [other] party's key material
     * and returns the resulting shared secret as a [ByteString].
     *
     * Use [generateSharedSecretBlocking] when calling from non-suspending code.
     */
    public suspend fun generateSharedSecret(other: K): ByteString {
        return generateSharedSecretToByteArray(other).asByteString()
    }

    /**
     * Performs key agreement with the [other] party's key material
     * and returns the resulting shared secret as a [ByteArray].
     *
     * Use [generateSharedSecretToByteArray] when calling from suspending code.
     */
    public fun generateSharedSecretToByteArrayBlocking(other: K): ByteArray

    /**
     * Performs key agreement with the [other] party's key material
     * and returns the resulting shared secret as a [ByteString].
     *
     * Use [generateSharedSecret] when calling from suspending code.
     */
    public fun generateSharedSecretBlocking(other: K): ByteString {
        return generateSharedSecretToByteArrayBlocking(other).asByteString()
    }
}
