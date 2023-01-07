package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*

internal abstract class JdkKeyPairGenerator<K : Key>(
    private val state: JdkCryptographyState,
    algorithm: String,
) : KeyGenerator<K> {
    private val keyPairGenerator = state.keyPairGenerator(algorithm)

    protected abstract fun JKeyPairGenerator.init()

    protected abstract fun JKeyPair.convert(): K

    final override fun generateKeyBlocking(): K {
        return keyPairGenerator.use {
            it.init()
            it.generateKeyPair()
        }.convert()
    }

    override suspend fun generateKey(): K {
        return state.execute { generateKeyBlocking() }
    }
}
