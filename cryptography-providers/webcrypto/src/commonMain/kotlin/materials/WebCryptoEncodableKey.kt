/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal abstract class WebCryptoEncodableKey<F : EncodingFormat>(
    private val key: CryptoKey,
    private val keyProcessor: WebCryptoKeyProcessor<F>,
) : Encodable<F> {
    override suspend fun encodeToByteArray(format: F): ByteArray = keyProcessor.afterEncoding(
        algorithm = key.algorithm,
        format = format,
        key = WebCrypto.exportKey(keyProcessor.stringFormat(format), key)
    )

    override fun encodeToByteArrayBlocking(format: F): ByteArray = nonBlocking()
}
