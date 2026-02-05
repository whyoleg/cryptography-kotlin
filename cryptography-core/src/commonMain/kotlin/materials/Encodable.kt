/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encodable<F : EncodingFormat> {
    public suspend fun encodeToByteArray(format: F): ByteArray {
        return encodeToByteArrayBlocking(format)
    }

    public fun encodeToByteArrayBlocking(format: F): ByteArray

    public suspend fun encodeToByteString(format: F): ByteString {
        return encodeToByteArray(format).asByteString()
    }

    public fun encodeToByteStringBlocking(format: F): ByteString {
        return encodeToByteArrayBlocking(format).asByteString()
    }
}
