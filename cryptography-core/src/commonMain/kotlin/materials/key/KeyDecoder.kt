/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyDecoder<KF : KeyFormat, K : Key> {
    public suspend fun decodeFromByteArray(format: KF, bytes: ByteArray): K = decodeFromByteArrayBlocking(format, bytes)
    public fun decodeFromByteArrayBlocking(format: KF, bytes: ByteArray): K

    public suspend fun decodeFromByteString(format: KF, byteString: ByteString): K =
        decodeFromByteArray(format, byteString.asByteArray())

    public fun decodeFromByteStringBlocking(format: KF, byteString: ByteString): K =
        decodeFromByteArrayBlocking(format, byteString.asByteArray())

    @Deprecated(
        "Renamed to decodeFromByteArray",
        ReplaceWith("decodeFromByteArray(format, data)"),
        level = DeprecationLevel.ERROR,
    )
    public suspend fun decodeFrom(format: KF, data: ByteArray): K = decodeFromByteArray(format, data)

    @Deprecated(
        "Renamed to decodeFromByteArrayBlocking",
        ReplaceWith("decodeFromByteArrayBlocking(format, data)"),
        level = DeprecationLevel.ERROR,
    )
    public fun decodeFromBlocking(format: KF, data: ByteArray): K = decodeFromByteArrayBlocking(format, data)
}
