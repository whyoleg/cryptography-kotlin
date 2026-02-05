/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal abstract class JdkPublicKeyDecoder<F : EncodingFormat, K>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : Decoder<F, K> {
    private val keyFactory = state.keyFactory(algorithm)

    protected fun decode(spec: KeySpec): K = keyFactory.use { it.generatePublic(spec) }.convert()

    protected fun decodeFromDer(input: ByteArray): K = decode(X509EncodedKeySpec(input))

    protected abstract fun JPublicKey.convert(): K
}
