/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyDecoder<KF : KeyFormat, K : Key> : MaterialDecoder<KF, K> {
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
