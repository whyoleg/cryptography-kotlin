/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoKeyDecoder<KF : KeyFormat, K : Key>(
    private val algorithm: Algorithm,
    private val keyProcessor: WebCryptoKeyProcessor<KF>,
    private val keyWrapper: WebCryptoKeyWrapper<K>,
) : KeyDecoder<KF, K> {
    override suspend fun decodeFromByteArray(format: KF, bytes: ByteArray): K = keyWrapper.wrap(
        WebCrypto.importKey(
            format = keyProcessor.stringFormat(format),
            keyData = keyProcessor.beforeDecoding(algorithm, format, bytes),
            algorithm = algorithm,
            extractable = true,
            keyUsages = keyWrapper.usages
        )
    )

    override fun decodeFromByteArrayBlocking(format: KF, bytes: ByteArray): K = nonBlocking()
}
