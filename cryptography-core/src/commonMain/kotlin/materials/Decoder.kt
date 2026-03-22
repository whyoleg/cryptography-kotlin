/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

/**
 * Decodes cryptographic material of type [M] from an encoded byte representation in a given [EncodingFormat].
 *
 * For the encoding counterpart, see [Encodable].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decoder<F : EncodingFormat, M> {
    /**
     * Decodes material from the given [bytes] encoded in the specified [format]
     * and returns the resulting instance of [M].
     *
     * Throws an exception if the bytes are not valid for the given format or do not represent well-formed material.
     *
     * Use [decodeFromByteArrayBlocking] when calling from non-suspending code.
     */
    public suspend fun decodeFromByteArray(format: F, bytes: ByteArray): M {
        return decodeFromByteArrayBlocking(format, bytes)
    }

    /**
     * Decodes material from the given [bytes] encoded in the specified [format]
     * and returns the resulting instance of [M].
     *
     * Throws an exception if the bytes are not valid for the given format or do not represent well-formed material.
     *
     * Use [decodeFromByteArray] when calling from suspending code.
     */
    public fun decodeFromByteArrayBlocking(format: F, bytes: ByteArray): M

    /**
     * Decodes material from the given [byteString] encoded in the specified [format]
     * and returns the resulting instance of [M].
     *
     * Throws an exception if the bytes are not valid for the given format or do not represent well-formed material.
     *
     * Use [decodeFromByteStringBlocking] when calling from non-suspending code.
     */
    public suspend fun decodeFromByteString(format: F, byteString: ByteString): M {
        return decodeFromByteArray(format, byteString.asByteArray())
    }

    /**
     * Decodes material from the given [byteString] encoded in the specified [format]
     * and returns the resulting instance of [M].
     *
     * Throws an exception if the bytes are not valid for the given format or do not represent well-formed material.
     *
     * Use [decodeFromByteString] when calling from suspending code.
     */
    public fun decodeFromByteStringBlocking(format: F, byteString: ByteString): M {
        return decodeFromByteArrayBlocking(format, byteString.asByteArray())
    }
}
