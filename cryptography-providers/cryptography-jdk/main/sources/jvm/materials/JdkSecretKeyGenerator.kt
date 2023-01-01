package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.materials.key.KeyGenerator
import javax.crypto.*
import javax.crypto.KeyGenerator as JavaxKeyGenerator

internal class JdkSecretKeyGenerator<K : Key>(
    private val state: JdkCryptographyState,
    algorithm: String,
    private val keyWrapper: (SecretKey) -> K,
    private val keyGeneratorInit: JavaxKeyGenerator.() -> Unit = { init(state.secureRandom) },
) : KeyGenerator<K> {
    private val keyGenerator = state.keyGenerator(algorithm)
    override fun generateKeyBlocking(): K {
        return keyWrapper(keyGenerator.use {
            it.keyGeneratorInit()
            it.generateKey()
        })
    }

    override suspend fun generateKey(): K {
        return state.execute { generateKeyBlocking() }
    }
}

