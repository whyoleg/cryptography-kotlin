/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

/**
 * Derives a secret from input keying material.
 *
 * The input is the keying material (e.g., a password or IKM), and the output is the derived secret.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation {
    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteArray].
     *
     * Use [deriveSecretToByteArrayBlocking] when calling from non-suspending code.
     */
    public suspend fun deriveSecretToByteArray(input: ByteArray): ByteArray {
        return deriveSecretToByteArrayBlocking(input)
    }

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteArray].
     *
     * Use [deriveSecretToByteArrayBlocking] when calling from non-suspending code.
     */
    public suspend fun deriveSecretToByteArray(input: ByteString): ByteArray {
        return deriveSecretToByteArray(input.asByteArray())
    }

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteString].
     *
     * Use [deriveSecretBlocking] when calling from non-suspending code.
     */
    public suspend fun deriveSecret(input: ByteArray): ByteString {
        return deriveSecretToByteArray(input).asByteString()
    }

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteString].
     *
     * Use [deriveSecretBlocking] when calling from non-suspending code.
     */
    public suspend fun deriveSecret(input: ByteString): ByteString {
        return deriveSecretToByteArray(input.asByteArray()).asByteString()
    }

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteArray].
     *
     * Use [deriveSecretToByteArray] when calling from suspending code.
     */
    public fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteArray].
     *
     * Use [deriveSecretToByteArray] when calling from suspending code.
     */
    public fun deriveSecretToByteArrayBlocking(input: ByteString): ByteArray {
        return deriveSecretToByteArrayBlocking(input.asByteArray())
    }

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteString].
     *
     * Use [deriveSecret] when calling from suspending code.
     */
    public fun deriveSecretBlocking(input: ByteArray): ByteString {
        return deriveSecretToByteArrayBlocking(input).asByteString()
    }

    /**
     * Derives a secret from the given [input] keying material
     * and returns the result as a [ByteString].
     *
     * Use [deriveSecret] when calling from suspending code.
     */
    public fun deriveSecretBlocking(input: ByteString): ByteString {
        return deriveSecretToByteArrayBlocking(input.asByteArray()).asByteString()
    }
}
