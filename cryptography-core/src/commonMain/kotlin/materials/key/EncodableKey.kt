/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key {
    public suspend fun encodeToByteArray(format: KF): ByteArray = encodeToByteArrayBlocking(format)
    public fun encodeToByteArrayBlocking(format: KF): ByteArray

    public suspend fun encodeToByteString(format: KF): ByteString = encodeToByteArray(format).asByteString()
    public fun encodeToByteStringBlocking(format: KF): ByteString = encodeToByteArrayBlocking(format).asByteString()

    @Deprecated(
        "Renamed to encodeToByteArray",
        ReplaceWith("encodeToByteArray(format)"),
        level = DeprecationLevel.ERROR,
    )
    public suspend fun encodeTo(format: KF): ByteArray = encodeToByteArray(format)

    @Deprecated(
        "Renamed to encodeToByteArrayBlocking",
        ReplaceWith("encodeToByteArrayBlocking(format)"),
        level = DeprecationLevel.ERROR,
    )
    public fun encodeToBlocking(format: KF): ByteArray = encodeToByteArrayBlocking(format)
}
