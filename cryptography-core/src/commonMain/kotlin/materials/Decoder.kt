/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decoder<F : EncodingFormat, M> {
    public suspend fun decodeFromByteArray(format: F, bytes: ByteArray): M {
        return decodeFromByteArrayBlocking(format, bytes)
    }

    public fun decodeFromByteArrayBlocking(format: F, bytes: ByteArray): M

    public suspend fun decodeFromByteString(format: F, byteString: ByteString): M {
        return decodeFromByteArray(format, byteString.asByteArray())
    }

    public fun decodeFromByteStringBlocking(format: F, byteString: ByteString): M {
        return decodeFromByteArrayBlocking(format, byteString.asByteArray())
    }
}
