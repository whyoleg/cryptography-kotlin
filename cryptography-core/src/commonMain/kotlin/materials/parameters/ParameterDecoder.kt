/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.parameters

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ParameterDecoder<PF : ParameterFormat, P> {
    public suspend fun decodeFromByteArray(format: PF, bytes: ByteArray): P = decodeFromByteArrayBlocking(format, bytes)
    public fun decodeFromByteArrayBlocking(format: PF, bytes: ByteArray): P

    public suspend fun decodeFromByteString(format: PF, byteString: ByteString): P =
        decodeFromByteArray(format, byteString.asByteArray())

    public fun decodeFromByteStringBlocking(format: PF, byteString: ByteString): P =
        decodeFromByteArrayBlocking(format, byteString.asByteArray())
}
