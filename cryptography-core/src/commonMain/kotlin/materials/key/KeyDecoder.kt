/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyDecoder<KF : KeyFormat, K : Key> {
    public suspend fun decodeFrom(format: KF, input: ByteArray): K = decodeFromBlocking(format, input)
    public fun decodeFromBlocking(format: KF, input: ByteArray): K

    // `decodeFrom(_, String)` is useful for PEM format - do we need it?
    public suspend fun decodeFrom(format: KF, input: String): K = decodeFrom(format, input.encodeToByteArray())
    public suspend fun decodeFrom(format: KF, input: ByteString): K
    public suspend fun decodeFrom(format: KF, input: Source): K
}
