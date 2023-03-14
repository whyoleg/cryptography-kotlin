/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto.materials


import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoEncodableKey<KF : KeyFormat>(
    private val key: CryptoKey,
    private val keyFormat: (KF) -> String,
) : EncodableKey<KF> {
    override suspend fun encodeTo(format: KF): ByteArray {
        return WebCrypto.subtle.exportKeyBinary(
            format = keyFormat(format),
            key = key
        ).await()
    }

    override fun encodeToBlocking(format: KF): ByteArray = nonBlocking()
}
