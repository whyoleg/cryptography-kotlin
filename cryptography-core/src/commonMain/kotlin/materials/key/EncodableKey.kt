/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key {
    public suspend fun encodeTo(format: KF): ByteArray = encodeToBlocking(format)
    public fun encodeToBlocking(format: KF): ByteArray
}
