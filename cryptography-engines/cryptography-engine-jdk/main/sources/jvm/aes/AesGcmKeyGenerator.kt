package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.key.*
import javax.crypto.KeyGenerator

internal class AesGcmKeyGenerator(
    private val state: JdkCryptographyState,
    private val keySizeBits: Int,
) : SyncKeyGenerator<AES.GCM.Key> {
    private val keyGenerator: ThreadLocal<KeyGenerator> = threadLocal {
        state.provider.keyGenerator("AES").apply {
            init(keySizeBits, state.secureRandom)
        }
    }

    override fun generateKey(): AES.GCM.Key = AesGcmKey(state, keyGenerator.get().generateKey())
}

