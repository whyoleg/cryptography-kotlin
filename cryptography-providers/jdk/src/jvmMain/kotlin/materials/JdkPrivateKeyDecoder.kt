/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal abstract class JdkPrivateKeyDecoder<KF : KeyFormat, K : Key>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : KeyDecoder<KF, K> {
    protected val keyFactory = state.keyFactory(algorithm)

    protected fun decode(spec: KeySpec): K = keyFactory.use { it.generatePrivate(spec) }.convert()

    protected fun decodeFromDer(input: ByteArray): K = decode(PKCS8EncodedKeySpec(input))

    protected abstract fun JPrivateKey.convert(): K
}
