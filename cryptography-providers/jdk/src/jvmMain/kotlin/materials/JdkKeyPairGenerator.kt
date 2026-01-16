/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*

internal abstract class JdkKeyPairGenerator<K : Key>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : KeyGenerator<K> {
    private val keyPairGenerator = state.keyPairGenerator(algorithm)

    protected abstract fun JKeyPairGenerator.init()

    protected abstract fun JKeyPair.convert(): K

    final override fun generateBlocking(): K = keyPairGenerator.use {
        it.init()
        it.generateKeyPair()
    }.convert()
}
