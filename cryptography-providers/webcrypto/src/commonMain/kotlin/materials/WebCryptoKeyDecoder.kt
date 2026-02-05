/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoKeyDecoder<F : EncodingFormat, K>(
    private val algorithm: Algorithm,
    private val keyProcessor: WebCryptoKeyProcessor<F>,
    private val keyWrapper: WebCryptoKeyWrapper<K>,
) : Decoder<F, K> {
    override suspend fun decodeFromByteArray(format: F, bytes: ByteArray): K = keyWrapper.wrap(
        WebCrypto.importKey(
            format = keyProcessor.stringFormat(format),
            keyData = keyProcessor.beforeDecoding(algorithm, format, bytes),
            algorithm = algorithm,
            extractable = true,
            keyUsages = keyWrapper.usages
        )
    )

    override fun decodeFromByteArrayBlocking(format: F, bytes: ByteArray): K = nonBlocking()
}
