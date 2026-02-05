/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkSecretKeyDecoder<F : EncodingFormat, K>(
    private val algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
) : Decoder<F, K> {
    override fun decodeFromByteArrayBlocking(format: F, bytes: ByteArray): K = when (format.name) {
        "RAW" -> keyWrapper(SecretKeySpec(bytes, algorithm))
        else  -> error("$format is not supported")
    }
}
