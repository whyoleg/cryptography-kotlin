/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key, EncodableMaterial<KF> {
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
