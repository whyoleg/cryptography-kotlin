/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*

internal class JdkSecretKeyGenerator<K : Key>(
    state: JdkCryptographyState,
    algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
    private val keyGeneratorInit: JKeyGenerator.() -> Unit,
) : KeyGenerator<K> {
    private val keyGenerator = state.keyGenerator(algorithm)
    override fun generateKeyBlocking(): K = keyWrapper(keyGenerator.use {
        it.keyGeneratorInit()
        it.generateKey()
    })
}
