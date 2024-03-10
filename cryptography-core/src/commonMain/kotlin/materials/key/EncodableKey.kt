/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key {
    // TODO: deprecate
    public suspend fun encodeTo(format: KF): ByteArray = encodeToBlocking(format)
    public fun encodeToBlocking(format: KF): ByteArray

    // `encodeToString` is useful for PEM format - do we need it?
    public suspend fun encodeToString(format: KF): String = encodeToByteArray(format).decodeToString()
    public suspend fun encodeToByteArray(format: KF): ByteArray
    public suspend fun encodeToByteString(format: KF): ByteString
    public suspend fun encodeToSource(format: KF): Source
}
