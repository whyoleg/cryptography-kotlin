/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyDecoder<KF : KeyFormat, K : Key> {
    public suspend fun decodeFrom(format: KF, data: ByteArray): K = decodeFromBlocking(format, data)
    public fun decodeFromBlocking(format: KF, data: ByteArray): K
}
