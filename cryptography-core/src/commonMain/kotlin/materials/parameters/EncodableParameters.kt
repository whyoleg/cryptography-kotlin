/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.parameters

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableParameters<PF : ParameterFormat> {
    public suspend fun encodeToByteArray(format: PF): ByteArray = encodeToByteArrayBlocking(format)
    public fun encodeToByteArrayBlocking(format: PF): ByteArray

    public suspend fun encodeToByteString(format: PF): ByteString = encodeToByteArray(format).asByteString()
    public fun encodeToByteStringBlocking(format: PF): ByteString = encodeToByteArrayBlocking(format).asByteString()
}
