/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

/**
 * Represents cryptographic material that can be encoded to bytes in a given [EncodingFormat].
 * Typically implemented by key types to support encoding into formats like DER, PEM, JWK, or RAW.
 *
 * For the decoding counterpart, see [Decoder].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encodable<F : EncodingFormat> {
    /**
     * Encodes this material into a [ByteArray] in the specified [format].
     *
     * Use [encodeToByteArrayBlocking] when calling from non-suspending code.
     */
    public suspend fun encodeToByteArray(format: F): ByteArray {
        return encodeToByteArrayBlocking(format)
    }

    /**
     * Encodes this material into a [ByteArray] in the specified [format].
     *
     * Use [encodeToByteArray] when calling from suspending code.
     */
    public fun encodeToByteArrayBlocking(format: F): ByteArray

    /**
     * Encodes this material into a [ByteString] in the specified [format].
     *
     * Use [encodeToByteStringBlocking] when calling from non-suspending code.
     */
    public suspend fun encodeToByteString(format: F): ByteString {
        return encodeToByteArray(format).asByteString()
    }

    /**
     * Encodes this material into a [ByteString] in the specified [format].
     *
     * Use [encodeToByteString] when calling from suspending code.
     */
    public fun encodeToByteStringBlocking(format: F): ByteString {
        return encodeToByteArrayBlocking(format).asByteString()
    }
}
