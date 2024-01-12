/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoKeyDecoder<KF : KeyFormat, K : Key>(
    private val algorithm: Algorithm,
    private val keyUsages: Array<String>,
    private val keyFormat: (KF) -> String,
    private val keyWrapper: (CryptoKey) -> K,
) : KeyDecoder<KF, K> {
    override suspend fun decodeFrom(format: KF, input: ByteArray): K {
        return keyWrapper(WebCrypto.importKey(keyFormat(format), input, algorithm, true, keyUsages))
    }

    override fun decodeFromBlocking(format: KF, input: ByteArray): K = nonBlocking()
}
