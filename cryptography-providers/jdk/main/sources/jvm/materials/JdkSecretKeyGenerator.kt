package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*

internal class JdkSecretKeyGenerator<K : Key>(
    private val state: JdkCryptographyState,
    algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
    private val keyGeneratorInit: JKeyGenerator.() -> Unit,
) : KeyGenerator<K> {
    private val keyGenerator = state.keyGenerator(algorithm)
    override fun generateKeyBlocking(): K {
        return keyWrapper(keyGenerator.use {
            it.keyGeneratorInit()
            it.generateKey()
        })
    }
}

